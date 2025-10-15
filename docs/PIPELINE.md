1. Parse cli args
2. If directory -> list directory elements
    Else -> continue with list
3. prompt user for password with confirmation

4. Make iterator from list
Use iterator in order to:
	5. Transform string to path
	6. Filter for regular file
	7. Transform path to typed path
	8. If encrypted path, read content hash and store in hash map
	9. If plaintext path, hash content and only keep if hash map has no entry.
	10. Create encryption job with source file <-> target file path pair (obfuscated or not)
	11. Check if target file path exists.
	11. Encrypt file with xchacha20 and tlv header from source file path to target file path by streaming
	12. Validate encrypted file and create report
	13. Clean up encryption job based on report with atomic transactions (success: remove source file, failure: remove failed target file)
	14. pass result

15. Show final report


Notes:
- should use Result wrappers so that the pipelines continue without interruption on individual failures but include and pass on reasons for respective errors through the pipeline for the final report.
- maybe use higher order function or some kind of wrapper function to wrap each operation in a logger and metrics collector or something like that.
	

