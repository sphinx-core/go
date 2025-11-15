package core

const (
	// StatusInitializing indicates the blockchain is starting up and loading blocks
	StatusInitializing BlockchainStatus = iota

	// StatusSyncing indicates the blockchain is synchronizing with the network
	StatusSyncing

	// StatusRunning indicates the blockchain is fully operational and processing blocks
	StatusRunning

	// StatusStopped indicates the blockchain has been stopped
	StatusStopped

	// StatusForked indicates the blockchain has detected a fork and needs resolution
	StatusForked
)

const (
	// SyncModeFull synchronizes the entire blockchain history
	SyncModeFull SyncMode = iota

	// SyncModeFast synchronizes only block headers and recent state
	SyncModeFast

	// SyncModeLight synchronizes only block headers for light clients
	SyncModeLight
)

const (
	// ImportedBest indicates the block was imported as the new best block
	ImportedBest BlockImportResult = iota

	// ImportedSide indicates the block was imported as a side chain block
	ImportedSide

	// ImportedExisting indicates the block was already known
	ImportedExisting

	// ImportInvalid indicates the block failed validation
	ImportInvalid

	// ImportedError indicates an error occurred during import
	ImportError
)

const (
	// CacheTypeBlock stores recently accessed blocks
	CacheTypeBlock CacheType = iota

	// CacheTypeTransaction stores recently accessed transactions
	CacheTypeTransaction

	// CacheTypeReceipt stores transaction receipts
	CacheTypeReceipt

	// CacheTypeState stores recent state objects
	CacheTypeState
)
