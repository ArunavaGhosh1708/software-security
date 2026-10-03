import {db,transaction} from './db';
export async function cleanup(force=false) {
  return transaction(async t=>{
    const acquired=force?[{key:'forced'}]:await t.query(`INSERT INTO rate_limits(key,count,resets_at) VALUES('maintenance:retention',1,now()+interval '1 hour')
      ON CONFLICT(key) DO UPDATE SET resets_at=excluded.resets_at WHERE rate_limits.resets_at<now() RETURNING key`);
    if(!acquired.length)return false;
    await t.query("DELETE FROM runtime_events WHERE occurred_at<now()-interval '7 days'");
    await t.query("DELETE FROM scans WHERE created_at<now()-interval '30 days' AND status NOT IN ('queued','running')");
    await t.query("DELETE FROM findings WHERE last_seen<now()-interval '30 days' AND NOT EXISTS(SELECT 1 FROM scan_findings sf WHERE sf.finding_id=findings.id)");
    await t.query("DELETE FROM alerts WHERE last_seen<now()-interval '30 days'");
    await t.query("DELETE FROM github_deliveries WHERE received_at<now()-interval '7 days'");
    await t.query("DELETE FROM rate_limits WHERE resets_at<now() AND key<>'maintenance:retention'");
    return true;
  });
}
