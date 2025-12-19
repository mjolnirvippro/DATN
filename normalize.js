// Normalize payload to match mapping
return items.map(item => {
  const d = { ...item.json };

  // ioc_type/ioc_value -> ioc.{type,value}
  if (d.ioc_type && d.ioc_value) {
    d.ioc = d.ioc || {};
    d.ioc.type  = d.ioc.type  || d.ioc_type;
    d.ioc.value = d.ioc.value || d.ioc_value;
    delete d.ioc_type;
    delete d.ioc_value;
  }

  // observed_at -> @timestamp
  if (d.observed_at && !d['@timestamp']) {
    d['@timestamp'] = d.observed_at;
    delete d.observed_at;
  }

  // asn (top) -> geo.asn
  if (d.asn) {
    d.geo = d.geo || {};
    d.geo.asn = String(d.asn);
    delete d.asn;
  }

  // Summary block -> ai.*
  if (typeof d.summary === 'string' && !d.ai) {
    d.ai = {
      summary: d.summary,
      analysis: d.analysis,
      recommendations: d.recommendations,
      next_steps: d.next_steps,
    };
    delete d.summary;
    delete d.analysis;
    delete d.recommendations;
    delete d.next_steps;
  }

  // 🔧 FIX QUAN TRỌNG: alert_summary.ti_results phải là string, không được là object
  if (d.alert_summary && typeof d.alert_summary === 'object') {
    const as = d.alert_summary;

    if (as.ti_results && typeof as.ti_results === 'object') {
      const score   = as.ti_results.score;
      const verdict = as.ti_results.verdict;

      // Chuyển thành chuỗi ngắn gọn cho analyst, đúng kiểu "text"
      as.ti_results = `verdict=${verdict ?? 'unknown'}, score=${score ?? 'N/A'}`;
    }

    d.alert_summary = as;
  }

  return { json: d };
});
