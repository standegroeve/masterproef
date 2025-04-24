package security.benchmarks

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.io.File


fun main() {
    val tripleCount = 250
    val authCode = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJidHNhNG5ybzUwSGZuamVKRTlyZjlCRDZvSFBZVTRjdy02QmV5bDItbUNJIn0.eyJleHAiOjE3NDU0MTkyNjksImlhdCI6MTc0NTQwNDg2OSwiYXV0aF90aW1lIjoxNzQ1NDA0ODQxLCJqdGkiOiJiN2E3MmVjZS1kMmJkLTQ1YzUtOGUyNC04Yjg5NTExNWVmZTciLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgyODAvcmVhbG1zL2JvYiIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJmMmVjOGVlMy0zMzBhLTRlMjktYTM1Yy05NmY1MzczOGU0OGQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJwdWJsaWMtY2xpZW50Iiwic2lkIjoiYTM1OTFlOTEtNGVhOC00MGEwLWIyYjItNmI1MmE3OGU5OWFmIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjQyMDAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm93bmVyIiwiZGVmYXVsdC1yb2xlcy1ib2IiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiQm9iIERlbW8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJib2IiLCJnaXZlbl9uYW1lIjoiQm9iIiwiZmFtaWx5X25hbWUiOiJEZW1vIiwiZW1haWwiOiJib2JAZXhhbXBsZS5vcmcifQ.mWEOftoJsooA0UdJ22fjPH4dHKxPcsD2DLXTlToVoQn6kHkKKmL2-BAdyOkLJU2rwAsgh6TCnPdSRkasdOzFy34E5ldAbH1ysBlt-qWB_qwbhP6KUK8uDvH5DUO-gPT99GS7ZqfyX7RyFn4EFiqXBpgUPMaBFMTZ8Y5co-Mt88c_P9rIsRthz2GS5Ve8gghB_IA87ausq7w3nOBf6S7s6ZyThfNoyBUX5d7xOUDf61vTU3mFHv9wesiw1JnMYe6sFZLi8UMUEeJe6k4RfxCZLx0HJAZsDvAow_mHHv_3-BX_frd_0cN_p6URzITi_l8zV9f73poeA2TzmBHADxR_JQ"

     // val resultsWithoutApi = benchmarkWithoutAPI(tripleCount)

    // val resultsWithApi = benchmarkWithAPI(tripleCount, authCode)

    val resultsSum = benchmarkSum(tripleCount, authCode)

    // val timeX3dhAvg = benchmarkX3DH(tripleCount, 10)

//    val resultsX3DH = mapOf(
//        "times" to timeX3dhAvg,
//        "averageTime" to timeX3dhAvg.average()
//    )

    val mapper = jacksonObjectMapper()
    mapper.writerWithDefaultPrettyPrinter()
        .writeValue(File("benchmark_results.json"), resultsSum)

}