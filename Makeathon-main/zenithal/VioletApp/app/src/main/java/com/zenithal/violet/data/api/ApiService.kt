package com.zenithal.violet.data.api

import com.zenithal.violet.data.models.*
import retrofit2.http.*

interface ApiService {

    @GET("health")
    suspend fun healthCheck(): Map<String, Any>

    @POST("community/report")
    suspend fun reportUrl(@Body request: ReportRequest): ReportResponse

    @GET("community/reputation")
    suspend fun getReputation(@Query("url") url: String): ReputationResponse

    @POST("community/vote-safe")
    suspend fun voteSafe(@Body request: VoteRequest): VoteResponse

    @POST("community/vote-malicious")
    suspend fun voteMalicious(@Body request: VoteRequest): VoteResponse
}
