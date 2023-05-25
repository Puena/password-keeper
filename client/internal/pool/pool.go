package pool

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type workerTask func(ctx context.Context, history *models.History) error

type workerData struct {
	ctx     context.Context
	history *models.History
	idx     int
}

type worker struct {
	id     int
	in     chan workerData
	done   chan struct{}
	task   workerTask
	status *workerPoolStatus
	errors []error
	config *config.Config
	logger *zap.Logger
}

func (w *worker) Do() error {
	for {
		select {
		case <-w.done:
			w.logger.Info("worker got done signal", zap.Int("worker_id", w.id))
			return nil
		case data, ok := <-w.in:
			if !ok {
				w.logger.Info("input channel has been closed", zap.Int("worker_id", w.id))
				return nil
			}
			w.logger.Info("worker start handle history", zap.Int("worker_id", w.id), zap.String("chest_id", data.history.ChestID), zap.Int32("operation_type", int32(data.history.OperationType)), zap.String("history_id", data.history.ID))
			err := w.task(data.ctx, data.history)
			if err != nil {
				w.status.AddErrors(1)
				w.logger.Info("worker failed while trying to handle history", zap.Int("worker_id", w.id), zap.Error(err))
			}
			w.status.AddFinished(1)
			w.status.WriteStatus()
			w.errors[data.idx] = err
		}
	}

}

type historyWorkerPool struct {
	ctxPool context.Context
	in      chan workerData
	errors  []error
	done    chan struct{}
	status  *workerPoolStatus
	config  *config.Config
	logger  *zap.Logger
}

func NewHistoryWorkerPool(ctx context.Context, config *config.Config, logger *zap.Logger) *historyWorkerPool {
	return &historyWorkerPool{
		ctxPool: ctx,
		in:      make(chan workerData),
		done:    make(chan struct{}),
		status:  newWorkerPoolStatus(),
		config:  config,
		logger:  logger,
	}
}

func (p *historyWorkerPool) produce(ctx context.Context, history []*models.History) {
	for i, h := range history {
		p.in <- workerData{
			idx:     i,
			ctx:     ctx,
			history: h,
		}
	}
	close(p.in)
}

func (p *historyWorkerPool) SetStatusOutput(w io.Writer) {
	p.status.SetOutput(w)
}

func (p *historyWorkerPool) Start(taskCtx context.Context, history []*models.History, task func(context.Context, *models.History) error) error {
	total := len(history)
	p.status.SetTotal(total)
	p.errors = make([]error, total)
	defer p.status.WriteDone()

	g, grpCtx := errgroup.WithContext(taskCtx)
	defer close(p.done)

	go p.produce(grpCtx, history)

	config, err := p.config.ReadViperConfig()
	if err != nil {
		return err
	}
	for i := 0; i < config.BackgroundWorkers; i++ {
		w := &worker{
			id:     i,
			in:     p.in,
			done:   p.done,
			task:   task,
			status: p.status,
			errors: p.errors,
			config: p.config,
			logger: p.logger,
		}

		g.Go(w.Do)
	}
	return g.Wait()
}

func (p *historyWorkerPool) GetErrors() []error {
	return p.errors
}

type workerPoolStatusOption func(*workerPoolStatus)

func withTotal(total int) workerPoolStatusOption {
	return func(s *workerPoolStatus) {
		s.Total = new(int64)
		atomic.StoreInt64(s.Total, int64(total))
	}
}

func withOutput(output io.Writer) workerPoolStatusOption {
	return func(s *workerPoolStatus) {
		s.Output = output
	}
}

type workerPoolStatus struct {
	Total    *int64
	Finished *int64
	Errors   *int64
	Output   io.Writer
}

func newWorkerPoolStatus(options ...workerPoolStatusOption) *workerPoolStatus {
	status := &workerPoolStatus{
		Total:    new(int64),
		Finished: new(int64),
		Errors:   new(int64),
	}
	for _, option := range options {
		option(status)
	}
	return status
}

func (s *workerPoolStatus) SetOutput(output io.Writer) {
	if output == nil {
		return
	}
	s.Output = output
}

func (s *workerPoolStatus) WriteStatus() {
	if s.Output == nil {
		return
	}
	s.Output.Write([]byte(fmt.Sprintf("\rProcessed %d/%d ", atomic.LoadInt64(s.Finished), atomic.LoadInt64(s.Total))))
}

func (s *workerPoolStatus) WriteDone() {
	if s.Output == nil {
		return
	}
	s.Output.Write([]byte("\n"))
}

func (s *workerPoolStatus) SetTotal(total int) {
	atomic.StoreInt64(s.Total, int64(total))
}

func (s *workerPoolStatus) SetFinished(finished int) {
	atomic.StoreInt64(s.Finished, int64(finished))
}

func (s *workerPoolStatus) AddFinished(finished int) {
	atomic.AddInt64(s.Finished, int64(finished))
}

func (s *workerPoolStatus) SetErrors(errors int) {
	atomic.StoreInt64(s.Errors, int64(errors))
}

func (s *workerPoolStatus) AddErrors(errors int) {
	atomic.AddInt64(s.Errors, int64(errors))
}
