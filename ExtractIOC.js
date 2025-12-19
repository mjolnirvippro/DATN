// ExtractIOC - chuẩn hoá alert Wazuh & set @timestamp

return items.map(it => {

  const raw = it.json?.body ?? it.json ?? {};


  const hit    = raw._source || raw;
  const fields = raw.fields || {};


  if (!hit['@timestamp']) {
    let ts = null;

    if (hit['@timestamp']) {
      ts = hit['@timestamp'];
    } else if (Array.isArray(fields.timestamp) && fields.timestamp[0]) {
      // trường hợp gửi nguyên hit từ wazuh-alerts-*
      ts = fields.timestamp[0];
    } else if (hit.timestamp) {
      // trường hợp chỉ gửi _source vào webhook
      ts = hit.timestamp;
    }

    if (ts) {
      hit['@timestamp'] = ts;
    }
  }


  const a = hit;               
  const rule  = a.rule  || {};
  const agent = a.agent || {};

  const srcIp =
    a.data?.srcip ||
    a.data?.win?.system?.ipAddress ||
    a.src_ip ||
    a.source?.ip ||
    a.ip;

  const dstIp =
    a.data?.dstip ||
    a.data?.win?.eventdata?.destinationIp ||
    a.dst_ip ||
    a.destination?.ip;

  const dstPort =
    a.data?.dstport ||
    a.data?.win?.eventdata?.destinationPort ||
    a.dst_port ||
    a.destination?.port ||
    0;

  const out = {
    ...a,
    rule,
    agent,
    src_ip: srcIp,
    dst_ip: dstIp,
    dst_port: dstPort,
    ip: srcIp,
    isPrivate: false,
  };

  return { json: out };
});

