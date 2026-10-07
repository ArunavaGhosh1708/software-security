import {db} from './db';
export async function analytics(org:string,project:string|null) {
  const scans=await db.query(`SELECT date_trunc('day',created_at) AS day,count(*)::integer AS scans,
    count(*) FILTER(WHERE gate='pass')::integer AS passed,count(*) FILTER(WHERE gate='fail')::integer AS failed,
    count(*) FILTER(WHERE gate='incomplete')::integer AS incomplete
    FROM scans WHERE organization_id=$1 AND ($2::uuid IS NULL OR project_id=$2) AND created_at>now()-interval '30 days'
    GROUP BY 1 ORDER BY 1`,[org,project]);
  const resolutions=(await db.query(`SELECT count(*)::integer AS resolved,
    avg(extract(epoch FROM resolved_at-first_seen)/86400) AS mean_resolution_days FROM findings
    WHERE organization_id=$1 AND ($2::uuid IS NULL OR project_id=$2) AND status='resolved' AND resolved_at>now()-interval '30 days'`,[org,project]))[0];
  return {scans,resolutions,window_days:30,limitation:'Resolution time uses first detection for findings currently resolved. Reopen cycles are not separate incidents; results within retention are not a complete historical risk trend.'};
}
