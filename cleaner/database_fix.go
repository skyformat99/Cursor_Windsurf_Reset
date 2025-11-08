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
			log.Debug().Str("connection", connStr).Err(err).Msg("尝试连接数据库失败")
			continue
		}

		if err := db.Ping(); err != nil {
			db.Close()
			log.Debug().Str("connection", connStr).Err(err).Msg("Ping数据库失败")
			continue
		}

		log.Debug().Str("connection", connStr).Msg("成功连接到数据库")

		tx, err := db.Begin()
		if err != nil {
			db.Close()
			log.Error().Err(err).Msg("开始事务失败")
			continue
		}

		tables, err := tx.Query("SELECT name FROM sqlite_master WHERE type='table'")
		if err != nil {
			log.Error().Err(err).Msg("获取表列表失败")
			tx.Rollback()
			db.Close()
			continue
		}

		var tableNames []string
		for tables.Next() {
			var tableName string
			if err := tables.Scan(&tableName); err != nil {
				log.Warn().Err(err).Msg("读取表名失败")
				continue
			}
			if !hasPrefix(tableName, "sqlite_") {
				tableNames = append(tableNames, tableName)
			}
		}
		tables.Close()

		if len(tableNames) == 0 {
			log.Warn().Str("path", dbPath).Msg("数据库中没有找到用户表")
			tx.Rollback()
			db.Close()
			return false, 0, true
		}

		cleanedRecords := 0
		// cachePatterns := e.config.CleaningOptions.CacheTablePatterns

		_ = cleanedRecords

		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Msg("提交事务失败")
			tx.Rollback()
			db.Close()
			return false, 0, false
		}

		if cleanedRecords > 0 {
			log.Info().Str("path", dbPath).Msg("优化数据库")
			if _, err := db.Exec("VACUUM"); err != nil {
				log.Warn().Err(err).Msg("执行VACUUM失败")
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
