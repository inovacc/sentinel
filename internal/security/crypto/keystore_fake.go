package crypto

import "sync"

// FakeKeyStore is an in-memory KeyStore for tests. It is plain Go (not build-
// tagged) so any package's tests can use it. available controls Available().
type FakeKeyStore struct {
	mu        sync.Mutex
	data      map[string][]byte
	available bool
}

// NewFakeKeyStore returns an available, empty fake.
func NewFakeKeyStore() *FakeKeyStore {
	return &FakeKeyStore{data: map[string][]byte{}, available: true}
}

// SetAvailable toggles what Available() reports (to exercise the fallback path).
func (f *FakeKeyStore) SetAvailable(v bool) { f.mu.Lock(); f.available = v; f.mu.Unlock() }

func (f *FakeKeyStore) key(service, account string) string { return service + "\x00" + account }

func (f *FakeKeyStore) Get(service, account string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[f.key(service, account)]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (f *FakeKeyStore) Set(service, account string, secret []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(secret))
	copy(cp, secret)
	f.data[f.key(service, account)] = cp
	return nil
}

func (f *FakeKeyStore) Delete(service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, f.key(service, account))
	return nil
}

func (f *FakeKeyStore) Available() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available
}
