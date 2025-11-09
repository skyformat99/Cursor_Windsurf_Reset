package cleaner

import (
	"database/sql"
)

// cleanSQLiteDatabaseAdvancedFixed
func (e *Engine) cleanSQLiteDatabaseAdvancedFixed(dbPath string, keywords []string) (bool, int, bool) {
	connectionStrings := []string{
		dbPath + "?_journal=WAL&_timeout=5000",
		dbPath + "?mode=rw",
		dbPath, //
	}

	for _, connStr := range connectionStrings {
		db, err := sql.Open("sqlite", connStr)
		if err != nil {
			logDebug("尝试连接数据库失败", "connection", connStr, "error", err)
			continue
		}

		if err := db.Ping(); err != nil {
			db.Close()
			logDebug("Ping数据库失败", "connection", connStr, "error", err)
			continue
		}

		logDebug("成功连接到数据库", "connection", connStr)

		tx, err := db.Begin()
		if err != nil {
			db.Close()
			logError("开始事务失败", "error", err)
			continue
		}

		tables, err := tx.Query("SELECT name FROM sqlite_master WHERE type='table'")
		if err != nil {
			logError("获取表列表失败", "error", err)
			tx.Rollback()
			db.Close()
			continue
		}

		var tableNames []string
		for tables.Next() {
			var tableName string
			if err := tables.Scan(&tableName); err != nil {
				logWarn("读取表名失败", "error", err)
				continue
			}
			if !hasPrefix(tableName, "sqlite_") {
				tableNames = append(tableNames, tableName)
			}
		}
		tables.Close()

		if len(tableNames) == 0 {
			logWarn("数据库中没有找到用户表", "path", dbPath)
			tx.Rollback()
			db.Close()
			return false, 0, true
		}

		cleanedRecords := 0
		// cachePatterns := e.config.CleaningOptions.CacheTablePatterns

		_ = cleanedRecords

		if err := tx.Commit(); err != nil {
			logError("提交事务失败", "error", err)
			tx.Rollback()
			db.Close()
			return false, 0, false
		}

		if cleanedRecords > 0 {
			logInfo("优化数据库", "path", dbPath)
			if _, err := db.Exec("VACUUM"); err != nil {
				logWarn("执行VACUUM失败", "error", err)
			}
		}
		db.Close()
		return cleanedRecords > 0, cleanedRecords, true
	}
	return false, 0, false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
}
