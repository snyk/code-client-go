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
package scan

import (
	"time"

	"github.com/google/uuid"
)

type tracker struct {
	progressID ProgressID
	lastReport time.Time
	finished   bool
	progresses ProgressChannels
}

func NewTracker(progresses ProgressChannels) *tracker {
	return &tracker{
		progresses: progresses,
		finished:   false,
	}
}

func (t *tracker) Begin(title, message string) {
	progressToken := uuid.New().String()

	t.progressID = ProgressID(progressToken)
	t.progresses <- Progress{
		ID:   t.progressID,
		Kind: ProgressKindInit,
	}

	t.progresses <- Progress{
		ID:      t.progressID,
		Kind:    ProgressKindBegin,
		Title:   title,
		Message: message,
	}
	t.lastReport = time.Now()
}

func (t *tracker) Report(message string) {
	// throttle progress so it's sent once a second
	if time.Now().Before(t.lastReport.Add(time.Second)) {
		return
	}
	t.progresses <- Progress{
		ID:      t.progressID,
		Kind:    ProgressKindReport,
		Message: message,
	}
	t.lastReport = time.Now()
}

func (t *tracker) End(message string) {
	// make sure we don't end the progress more than once
	if t.finished {
		return
	}
	t.finished = true
	t.progresses <- Progress{
		ID:      t.progressID,
		Kind:    ProgressKindEnd,
		Message: message,
	}
}
