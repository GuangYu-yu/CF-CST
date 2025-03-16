package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// DBManager 数据库管理器
type DBManager struct {
	db   *leveldb.DB
	mu   sync.Mutex
	path string
}

var (
	dbManager *DBManager
	once      sync.Once
)

// GetDBManager 获取数据库管理器单例
func GetDBManager() *DBManager {
	once.Do(func() {
		dbManager = &DBManager{
			path: "cfspeed.db",
		}
	})
	return dbManager
}

// Open 打开数据库
func (m *DBManager) Open() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db != nil {
		return nil
	}

	opts := &opt.Options{
		WriteBuffer: 32 * 1024 * 1024,
		BlockSize:   32 * 1024,
		Compression: opt.SnappyCompression,
	}

	db, err := leveldb.OpenFile(m.path, opts)
	if err != nil {
		return fmt.Errorf("打开数据库失败: %v", err)
	}
	m.db = db
	return nil
}

// Close 关闭数据库
func (m *DBManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db != nil {
		if err := m.db.Close(); err != nil {
			return fmt.Errorf("关闭数据库失败: %v", err)
		}
		m.db = nil
		if err := os.RemoveAll(m.path); err != nil {
			return fmt.Errorf("删除数据库文件失败: %v", err)
		}
	}
	return nil
}

// GetDB 获取数据库实例
func (m *DBManager) GetDB() *leveldb.DB {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.db
}