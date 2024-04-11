/*
 * © 2022 Snyk Limited All rights reserved.
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

package observability

import (
	"context"
	"sync"
)

type spanRecorderCodeImpl struct {
	mutex sync.Mutex
	spans []Span
}

func newSpanRecorderNew() SpanRecorder {
	return &spanRecorderCodeImpl{mutex: sync.Mutex{}, spans: []Span{}}
}

func (s *spanRecorderCodeImpl) Record(span Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = append(s.spans, span)
}

func (s *spanRecorderCodeImpl) Spans() []Span {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.spans
}

func (s *spanRecorderCodeImpl) ClearSpans() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spans = []Span{}
}

func (s *spanRecorderCodeImpl) Finish(span Span) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, currSpan := range s.spans {
		if span == currSpan {
			currSpan.Finish()
		}
	}
}

type instrumentor struct {
	SpanRecorder SpanRecorder
}

type SpanRecorder interface {
	Record(span Span)
	Spans() []Span
	ClearSpans()
	Finish(span Span)
}

func NewInstrumentor() Instrumentor {
	return &instrumentor{SpanRecorder: newSpanRecorderNew()}
}

func (i *instrumentor) Record(span Span) {
	i.SpanRecorder.Record(span)
}

func (i *instrumentor) Spans() []Span {
	return i.SpanRecorder.Spans()
}

func (i *instrumentor) ClearSpans() {
	i.SpanRecorder.ClearSpans()
}

func (i *instrumentor) StartSpan(ctx context.Context, operation string) Span {
	span := NewNoopSpan(ctx, operation, "", false, false)
	span.StartSpan(ctx)
	i.SpanRecorder.Record(span)
	return span
}

func (i *instrumentor) NewTransaction(ctx context.Context, txName string, operation string) Span {
	s := NewNoopSpan(ctx, operation, txName, false, false)
	i.SpanRecorder.Record(s)
	return s
}

func (i *instrumentor) Finish(span Span) {
	i.SpanRecorder.Finish(span)
}
