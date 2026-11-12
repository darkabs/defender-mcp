import json
import auth
import vt
import logging
import asyncio

#urlss = ["https://eicar.org"]

async def get_url_info(urls: list[str])-> list[dict]:
    results=[]
    async with vt.Client(auth.api_key_vt) as client:
        for url in urls:
            try:
                url_id = vt.url_id(url)
                response = await client.get_object_async("/urls/{}".format(url_id))
                
            except Exception:
                logging.exception("Unable to get url info")
                results.append({"URL":url, "Error":"Lookup failed"})
                continue
                
            
            analysis=[]
            scanner_analysis = getattr(response, "last_analysis_results", None) or {}
            
            for value in scanner_analysis.values():
                if value.get("category") not in {"malicious", "suspicious"}:
                    continue
                analysis.append({
                    "Engine":value.get("engine_name"),
                    "Result":value.get("result"),
                    "Category":value.get("category")
                })
            
            stats = getattr(response, "last_analysis_stats", None)
            analysis_date = getattr(response, "last_analysis_date", None)               
            results.append({
                "URL":url,
                "Report": {
                    "Analysis Stats": dict(stats) if stats is not None else None,
                    "Last Analysis Date" : (analysis_date.isoformat() if analysis_date is not None else None),
                    "Final URL": getattr(response, "last_final_url", None),
                    "Analysis": analysis
                    }
            })
        return results

    
# if __name__ == "__main__":
#     response = asyncio.run(get_url_info(urlss))
#     #results = summary_hash_report(response)
#     print(json.dumps(response, indent=2))

