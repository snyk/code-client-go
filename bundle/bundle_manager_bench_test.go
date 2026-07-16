/*
 * © 2024 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bundle_test

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/internal/deepcode/mocks"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/observability/mocks"
	trackerMocks "github.com/snyk/code-client-go/scan/mocks"
)

// benchFileCount and benchFileSize describe a synthetic source tree used to
// exercise the file-reading + hashing hot path of Create.
const (
	benchFileCount = 3000
	benchFileSize  = 4 * 1024
)

// makeBenchTree writes benchFileCount .java files of benchFileSize bytes each
// (with distinct content so hashes differ) and returns their absolute paths.
func makeBenchTree(b *testing.B) (rootPath string, files []string) {
	b.Helper()
	rootPath = b.TempDir()
	files = make([]string, 0, benchFileCount)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < benchFileCount; i++ {
		// Spread files across subdirectories like a real project.
		dir := filepath.Join(rootPath, "pkg", strconv.Itoa(i%64))
		_ = os.MkdirAll(dir, 0700)
		p := filepath.Join(dir, "file"+strconv.Itoa(i)+".java")
		content := make([]byte, benchFileSize)
		for j := range content {
			content[j] = byte('a' + rng.Intn(26))
		}
		if err := os.WriteFile(p, content, 0600); err != nil {
			b.Fatal(err)
		}
		files = append(files, p)
	}
	return rootPath, files
}

func newBenchManager(b *testing.B) bundle.BundleManager {
	b.Helper()
	ctrl := gomock.NewController(b)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().Context().Return(context.Background()).AnyTimes()
	mockClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
	mockClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".java"},
	}, nil).AnyTimes()
	mockClient.EXPECT().CreateBundle(gomock.Any(), gomock.Any()).Return("bench-hash", []string{}, nil).AnyTimes()
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	mockTracker := trackerMocks.NewMockTracker(ctrl)
	mockTracker.EXPECT().Begin(gomock.Any(), gomock.Any()).AnyTimes()
	mockTracker.EXPECT().End(gomock.Any()).AnyTimes()
	mockTrackerFactory := trackerMocks.NewMockTrackerFactory(ctrl)
	mockTrackerFactory.EXPECT().GenerateTracker().Return(mockTracker).AnyTimes()

	logger := zerolog.Nop()
	return bundle.NewBundleManager(mockClient, &logger, mockInstrumentor, mockErrorReporter, mockTrackerFactory)
}

// BenchmarkCreate_Parallel measures the production (parallel) Create.
func BenchmarkCreate_Parallel(b *testing.B) {
	rootPath, files := makeBenchTree(b)
	mgr := newBenchManager(b)
	ctx := context.Background()
	changed := map[string]bool{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mgr.Create(ctx, "req", rootPath, sliceToChannel(files), changed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCreate_Sequential replicates the original, single-threaded Create
// loop using only the same public helpers it relied on. It is the baseline the
// parallel implementation is compared against.
func BenchmarkCreate_Sequential(b *testing.B) {
	rootPath, files := makeBenchTree(b)
	changed := map[string]bool{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		paths := sliceToChannel(files)
		fileHashes := make(map[string]string)
		bundleFiles := make(map[string]deepcode.BundleFile)
		var limitToFiles []string
		for absoluteFilePath := range paths {
			// Original IsSupported reduces to an extension/config-file lookup
			// once filters are loaded; the bench tree only contains ".java".
			if filepath.Ext(absoluteFilePath) != ".java" {
				continue
			}
			fileInfo, err := os.Stat(absoluteFilePath)
			if err != nil {
				continue
			}
			if fileInfo.Size() == 0 || fileInfo.Size() > 1024*1024 {
				continue
			}
			fileContent, err := os.ReadFile(absoluteFilePath)
			if err != nil {
				continue
			}
			relativePath, _ := util.ToRelativeUnixPath(rootPath, absoluteFilePath)
			relativePath = util.EncodePath(relativePath)
			bundleFile, _ := deepcode.BundleFileFrom(fileContent, true)
			bundleFiles[relativePath] = bundleFile
			fileHashes[relativePath] = bundleFile.Hash
			if changed[absoluteFilePath] {
				limitToFiles = append(limitToFiles, relativePath)
			}
		}
		_ = bundleFiles
		_ = fileHashes
		_ = limitToFiles
	}
}

// The benchmarks below model the I/O-bound regime that dominates on Windows,
// where each file's open/stat/read is high-latency blocking work rather than
// CPU work. They isolate the scheduling structure of Create (sequential loop vs
// the bounded worker pool it now uses) from the host filesystem so the
// parallelisation speed-up is observable on any platform. windowsLikeIOLatency
// approximates a single combined open+stat+read round-trip on Windows.
const windowsLikeIOLatency = 120 * time.Microsecond

func createWorkerCountForBench() int {
	n := runtime.GOMAXPROCS(0) * 4
	if n < 4 {
		n = 4
	}
	if n > 32 {
		n = 32
	}
	return n
}

// BenchmarkIOBound_Sequential models the original loop: one blocking I/O per
// file, performed serially.
func BenchmarkIOBound_Sequential(b *testing.B) {
	files := make([]string, benchFileCount)
	for i := range files {
		files[i] = strconv.Itoa(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for range files {
			time.Sleep(windowsLikeIOLatency)
		}
	}
}

// BenchmarkIOBound_Parallel models the new loop: the same blocking I/O per file
// spread across the worker pool, overlapping the latency.
func BenchmarkIOBound_Parallel(b *testing.B) {
	files := make([]string, benchFileCount)
	for i := range files {
		files[i] = strconv.Itoa(i)
	}
	workers := createWorkerCountForBench()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jobs := make(chan string)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range jobs {
					time.Sleep(windowsLikeIOLatency)
				}
			}()
		}
		for _, f := range files {
			jobs <- f
		}
		close(jobs)
		wg.Wait()
	}
}
