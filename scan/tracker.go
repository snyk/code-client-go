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

type ProgressID string

type ProgressKind string

const (
	ProgressKindInit   ProgressKind = "init"
	ProgressKindBegin  ProgressKind = "begin"
	ProgressKindReport ProgressKind = "report"
	ProgressKindEnd    ProgressKind = "end"
)

type Progress struct {
	ID   ProgressID   `json:"token"`
	Kind ProgressKind `json:"kind"`
	/**
	 * (Optional) Used to briefly inform about the kind of operation being performed.
	 *
	 * Examples: "Indexing" or "Linking dependencies".
	 */
	Title string `json:"titleWorkDoneProgressReport"`
	/**
	 * (Optional) Detailed progress message. Contains
	 * complementary information to the `title`.
	 *
	 * Examples: "3/25 files", "project/src/module2", "node_modules/some_dep".
	 * If unset, the previous progress message (if any) is still valid.
	 */
	Message string `json:"message,omitempty"`
}

type ProgressChannels chan Progress

//go:generate mockgen -destination=mocks/tracker.go -source=tracker.go -package mocks
type Tracker interface {
	Begin(title, message string)
	Report(message string)
	End(message string)
}
