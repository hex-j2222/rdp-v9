package com.gotohex.rdp.data.repository

import com.gotohex.rdp.data.db.ConnectionLogDao
import com.gotohex.rdp.data.model.ConnectionLog
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ConnectionLogRepository @Inject constructor(
    private val dao: ConnectionLogDao
) {
    /** Live stream of the 50 most-recent log entries (newest first). */
    fun getRecentLogs(): Flow<List<ConnectionLog>> = dao.getRecentLogs()

    /** Insert a new in-progress log entry and return its id. */
    suspend fun start(log: ConnectionLog): String {
        dao.insert(log)
        return log.id
    }

    /** Close a log entry with the final result when the session ends. */
    suspend fun finish(
        id: String,
        disconnectReason: String?,
        wasSuccessful: Boolean
    ) {
        dao.finalise(
            id = id,
            disconnectedAt = System.currentTimeMillis(),
            reason = disconnectReason,
            wasSuccessful = wasSuccessful
        )
    }

    /** Called on app startup to tidy up logs from previous crashes. */
    suspend fun closeOrphanedLogs() = dao.closeOrphanedLogs()

    /** Remove logs older than 30 days to keep the table small. */
    suspend fun purgeOld() {
        val thirtyDaysAgo = System.currentTimeMillis() - 30L * 24 * 60 * 60 * 1000
        dao.purgeOlderThan(thirtyDaysAgo)
    }

    suspend fun clearAll() = dao.clearAll()
}
