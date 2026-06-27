package com.gotohex.rdp.di

import android.content.Context
import androidx.room.Room
import com.gotohex.rdp.data.db.ConnectionLogDao
import com.gotohex.rdp.data.db.HexRdpDatabase
import com.gotohex.rdp.data.db.RdpProfileDao
import com.gotohex.rdp.data.db.MIGRATION_1_2
import com.gotohex.rdp.data.db.MIGRATION_2_3
import com.gotohex.rdp.data.db.MIGRATION_3_4
import com.gotohex.rdp.data.db.MIGRATION_4_5
import com.gotohex.rdp.data.db.MIGRATION_5_6  // BUG-3 FIX
import com.gotohex.rdp.data.db.MIGRATION_6_7  // BUG-3 FIX (acceptSelfSignedCertificate)
import com.gotohex.rdp.session.SessionTabManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): HexRdpDatabase =
        Room.databaseBuilder(
            context,
            HexRdpDatabase::class.java,
            HexRdpDatabase.DATABASE_NAME
        )
            .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7)  // BUG-3 FIX
            // BUG-N FIX: fallbackToDestructiveMigration(dropAllTables=true) destroys user data on
            // ANY migration failure (upgrade or downgrade). Use OnDowngrade only so that
            // failed upgrades crash fast and visibly instead of silently wiping data.
            .fallbackToDestructiveMigrationOnDowngrade(dropAllTables = true)
            .build()

    @Provides
    @Singleton
    fun provideRdpProfileDao(db: HexRdpDatabase): RdpProfileDao = db.rdpProfileDao()

    @Provides
    @Singleton
    fun provideConnectionLogDao(db: HexRdpDatabase): ConnectionLogDao = db.connectionLogDao()

    @Provides
    @Singleton
    fun provideSessionTabManager(): SessionTabManager = SessionTabManager()
}
