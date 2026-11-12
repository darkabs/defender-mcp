import httpx
import auth
#import asyncio
import logging

ENDPOINT = "https://hybrid-analysis.com/api/v2"
SEARCH = ENDPOINT + "/search/hash"

headers = {
    "api-key" : auth.api_key_ha,
    "Accept":"application/json",
    }
#hash_ = ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "6b330adda25939402eba8226930c947949e8d03ae7d045a6696b7b357bda3dbe"]

async def lookup_hash_report(file_hash: list[str]) -> list[dict]:
    results=[]
    async with httpx.AsyncClient() as client:
        for fh in file_hash:
            try: 
                response = await client.get(SEARCH, headers=headers,params={"hash":fh})
                response.raise_for_status()
                body = response.json()
            except Exception:
                logging.exception("Unable to lookup file hash")
                results.append({
                    "Hash":fh,
                    "Error": "Unable to lookup file hash"
                })
                continue
            
            results.append({
                "Hash": fh,
                "Response": body
            })
        return results
      

def summary_hash_report(body):
    
    results = []
    
    for item in body:
        
        if "Error" in item:
            results.append({
                "Hash":item['Hash'],
                "Error": item["Error"],
            })
            continue
            
        verdict_counts = {}
        reports=[]
         
        for key, values in item.get('Response').items():
            if key != "reports":
                continue
            
            for value in values:
                
                if value.get('state') != "SUCCESS":
                    continue
                if value.get('environment_id') != 140:
                    continue
                              
                verdict = value.get('verdict') or "unknown"
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                
                reports.append({
                    "ID":value.get('id'),
                    "Host Environment" : value.get('environment_description'),
                })
                
        summary={
            "hash":item['Hash'],
            "report": reports,
            "Verdict": verdict_counts
                }
        results.append(summary)

    return results

# if __name__ == "__main__":
#     response = asyncio.run(lookup_hash_report(hash_))
#     results = summary_hash_report(response)
#     print(results)

