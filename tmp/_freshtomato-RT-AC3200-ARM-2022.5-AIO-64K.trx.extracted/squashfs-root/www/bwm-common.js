var tabs = [];
var rx_max, rx_avg;
var tx_max, tx_avg;
var xx_max = 0;
var ifname;
var htmReady = 0;
var svgReady = 0;
var updating = 0;
var scaleMode = 0;
var scaleLast = -1;
var drawMode = 0;
var drawLast = -1;
var drawColor = 0;
var avgMode = 0;
var avgLast = -1;
var unitMode = 0;
var unitLast = -1;
var colorX = 0;
var colors = [['Blue &amp; Orange', '#003EBA', '#FF9000'], ['Blue &amp; Red', '#003EDD', '#CC4040'],
['Green &amp; Blue', '#118811', '#6495ed'], ['Red &amp; Black', '#d00', '#000'],
['Blue', '#22f', '#225'], ['Gray', '#000', '#999']
];
function xpsb(byt) {
if (cookie.get(cprefix+'unit') == 0)
return (byt / 125).toFixed(2)+' <small>kbit/s<\/small><br>('+(byt / 1024).toFixed(2)+' <small>KB/s<\/small>)';
else
return (byt / (125 * 1024)).toFixed(2)+' <small>Mbit/s<\/small><br>('+(byt / (1024 * 1024)).toFixed(2)+' <small>MB/s<\/small>)';
}
function showCTab() {
showTab('speed-tab-'+ifname);
}
function showSelectedOption(prefix, prev, now) {
var e;
elem.removeClass(prefix+prev, 'selected'); 
if ((e = E(prefix+now)) != null) {
elem.addClass(e, 'selected');
e.blur();
}
}
function showDraw() {
if (drawLast == drawMode)
return;
showSelectedOption('draw', drawLast, drawMode);
drawLast = drawMode;
}
function switchDraw(n) {
if ((!svgReady) || (updating))
return;
drawMode = n;
showDraw();
showCTab();
cookie.set(cprefix+'draw', drawMode);
}
function showUnit() {
if (unitMode == unitLast)
return;
showSelectedOption('unit', unitLast, unitMode);
unitLast = unitMode;
}
function switchUnit(n) {
if ((!svgReady) || (updating))
return;
unitMode = n;
showUnit();
cookie.set(cprefix+'unit', unitMode);
showCTab();
}
function showColor() {
E('drawcolor').innerHTML = colors[drawColor][0]+' &raquo;';
E('rx-name').style.borderBottom = '2px dashed '+colors[drawColor][1 + colorX];
E('tx-name').style.borderBottom = '2px dashed '+colors[drawColor][1 + (colorX ^ 1)];
}
function switchColor(rev) {
if ((!svgReady) || (updating))
return;
if (rev)
colorX ^= 1;
else
drawColor = (drawColor + 1) % colors.length;
showColor();
showCTab();
cookie.set(cprefix+'color', drawColor+','+colorX);
}
function showScale() {
if (scaleMode == scaleLast)
return;
showSelectedOption('scale', scaleLast, scaleMode);
scaleLast = scaleMode;
}
function switchScale(n) {
scaleMode = n;
showScale();
showTab('speed-tab-'+ifname);
cookie.set(cprefix+'scale', scaleMode);
}
function showAvg() {
if (avgMode == avgLast)
return;
showSelectedOption('avg', avgLast, avgMode);
avgLast = avgMode;
}
function switchAvg(n) {
if ((!svgReady) || (updating))
return;
avgMode = n;
showAvg();
showCTab();
cookie.set(cprefix+'avg', avgMode);
}
function tabSelect(name) {
if (!updating)
showTab(name);
}
function showTab(name) {
var h;
var max;
var i;
var rx, tx;
var e;
ifname = name.replace('speed-tab-', '');
cookie.set(cprefix+'tab', ifname, 14);
tabHigh(name);
h = speed_history[ifname];
if (!h)
return;
E('rx-current').innerHTML = xpsb(h.rx[h.rx.length - 1] / updateDiv);
E('rx-avg').innerHTML = xpsb(h.rx_avg);
E('rx-max').innerHTML = xpsb(h.rx_max);
E('tx-current').innerHTML = xpsb(h.tx[h.tx.length - 1] / updateDiv);
E('tx-avg').innerHTML = xpsb(h.tx_avg);
E('tx-max').innerHTML = xpsb(h.tx_max);
E('rx-total').innerHTML = scaleSize(h.rx_total);
E('tx-total').innerHTML = scaleSize(h.tx_total);
if (svgReady) {
max = (scaleMode ? MAX(h.rx_max, h.tx_max) : xx_max);
if (max > 12500)
max = Math.round((max + 12499) / 12500) * 12500;
else
max += 100;
updateSVG(h.rx, h.tx, max, drawMode, colors[drawColor][1 + colorX], colors[drawColor][1 + (colorX ^ 1)], updateInt, updateMaxL, updateDiv, avgMode, unitMode, clock);
}
}
function loadData() {
var old;
var t, e;
var name;
var i, j;
var changed;
xx_max = 0;
old = tabs;
tabs = [];
clock = new Date();
if (!speed_history)
speed_history = [];
else {
for (i in speed_history) {
var h = speed_history[i];
if ((typeof(h.rx) == 'undefined') || (typeof(h.tx) == 'undefined')) {
delete speed_history[i];
continue;
}
if ((h.rx_total == 0) && (h.tx_total == 0) && (h.up == 0)) {
delete speed_history[i];
continue;
}
if (typeof(h.hide) != 'undefined')
if (h.hide == 1)
continue;
if (updateReTotal) {
h.rx_total = h.rx_max = 0;
h.tx_total = h.tx_max = 0;
for (j = (h.rx.length - updateMaxL); j < h.rx.length; ++j) {
t = h.rx[j];
if (t > h.rx_max)
h.rx_max = t;
h.rx_total += t;
t = h.tx[j];
if (t > h.tx_max)
h.tx_max = t;
h.tx_total += t;
}
h.rx_avg = h.rx_total / (h.count ? h.count : updateMaxL);
h.tx_avg = h.tx_total / (h.count ? h.count : updateMaxL);
}
if (updateDiv > 1) {
h.rx_max /= updateDiv;
h.tx_max /= updateDiv;
h.rx_avg /= updateDiv;
h.tx_avg /= updateDiv;
}
if (h.rx_max > xx_max)
xx_max = h.rx_max;
if (h.tx_max > xx_max)
xx_max = h.tx_max;
t = i; 
if ((typeof(hostnamecache) != 'undefined') && (hostnamecache[i] != null)) {
if (nvram['cstats_labels'] != null ) {
if (nvram['cstats_labels'] == '1') 
t = hostnamecache[i];
if (nvram['cstats_labels'] == '0') 
t = hostnamecache[i]+' <small>['+i+']<\/small>';
}
}
else if (wl_ifidx(i) >= 0) {
t = 'WL <small>['+wl_display_ifname(wl_ifidx(i))+']<\/small>';
}
else if (nvram.lan_ifname == i)
t = 'LAN0 <small>['+i+']<\/small>';
else if (nvram.lan1_ifname == i)
t = 'LAN1 <small>['+i+']<\/small>';
else if (nvram.lan2_ifname == i)
t = 'LAN2 <small>['+i+']<\/small>';
else if (nvram.lan3_ifname == i)
t = 'LAN3 <small>['+i+']<\/small>';
else if ((nvram.wan_proto == 'pppoe') || (nvram.wan_proto == 'ppp3g') || (nvram.wan_proto == 'pptp') || (nvram.wan_proto == 'l2tp')
|| (nvram.wan2_proto == 'pppoe') || (nvram.wan2_proto == 'ppp3g') || (nvram.wan2_proto == 'pptp') || (nvram.wan2_proto == 'l2tp')
|| (nvram.wan3_proto == 'pppoe') || (nvram.wan3_proto == 'ppp3g') || (nvram.wan3_proto == 'pptp') || (nvram.wan3_proto == 'l2tp')
|| (nvram.wan4_proto == 'pppoe') || (nvram.wan4_proto == 'ppp3g') || (nvram.wan4_proto == 'pptp') || (nvram.wan4_proto == 'l2tp')
) {
if (nvram.wan_iface == i)
t = 'WAN0 <small>['+i+']<\/small>';
else if (nvram.wan2_iface == i)
t = 'WAN1 <small>['+i+']<\/small>';
else if (nvram.wan3_iface == i)
t = 'WAN2 <small>['+i+']<\/small>';
else if (nvram.wan4_iface == i)
t = 'WAN3 <small>['+i+']<\/small>';
}
else if ((nvram.wan_proto != 'disabled') || (nvram.wan2_proto != 'disabled')
|| (nvram.wan3_proto != 'disabled') || (nvram.wan4_proto != 'disabled')
) {
if (nvram.wan_ifname == i)
t = 'WAN0 <small>['+i+']<\/small>';
else if (nvram.wan2_ifname == i)
t = 'WAN1 <small>['+i+']<\/small>';
else if (nvram.wan3_ifname == i)
t = 'WAN2 <small>['+i+']<\/small>';
else if (nvram.wan4_ifname == i)
t = 'WAN3 <small>['+i+']<\/small>';
}
tabs.push(['speed-tab-'+i, t]);
}
tabs = tabs.sort(
function(a, b) {
if (a[1] < b[1])
return -1;
if (a[1] > b[1])
return 1;
return 0;
});
}
if (tabs.length == old.length) {
for (i = tabs.length - 1; i >= 0; --i) {
if (tabs[i][0] != old[i][0])
break;
}
changed = i > 0;
}
else
changed = 1;
if (changed)
E('tab-area').innerHTML = _tabCreate.apply(this, tabs);
if (((name = cookie.get(cprefix+'tab')) != null) && ((speed_history[name] != undefined))) {
showTab('speed-tab-'+name);
return;
}
if (tabs.length)
showTab(tabs[0][0]);
}
function initData() {
if (htmReady) {
loadData();
if (svgReady) {
E('graph').style.opacity = '1';
E('bwm-controls').style.opacity = '1';
}
}
}
function initCommon(defAvg, defDrawMode, defDrawColor, defUnit) {
drawMode = fixInt(cookie.get(cprefix+'draw'), 0, 1, defDrawMode);
showDraw();
var c = (cookie.get(cprefix+'color') || '').split(',');
if (c.length == 2) {
drawColor = fixInt(c[0], 0, colors.length - 1, defDrawColor);
colorX = fixInt(c[1], 0, 1, 0);
}
else
drawColor = defDrawColor;
showColor();
scaleMode = fixInt(cookie.get(cprefix+'scale'), 0, 1, 0);
showScale();
avgMode = fixInt(cookie.get(cprefix+'avg'), 1, 10, defAvg);
showAvg();
unitMode = fixInt(cookie.get(cprefix+'unit'), 0, 1, defUnit);
showUnit();
if ((nvram.wan_proto == 'disabled') || (nvram.wan_proto == 'wet'))
nvram.wan_ifname = '';
htmReady = 1;
initData();
E('refresh-spinner').style.display = 'none';
}
function populateCache() {
var s;
if (nvram['dhcpd_static'] != null ) {
s = nvram.dhcpd_static.split('>');
for (var i = 0; i < s.length; ++i) {
var t = s[i].split('<');
if ((t.length == 4) && (t[2] != ''))
hostnamecache[t[1]] = t[2].split(' ').splice(0,1);
}
}
if (typeof(dhcpd_lease) != 'undefined') {
for (var j = 0; j < dhcpd_lease.length; ++j) {
if (dhcpd_lease[j][0] != '')
hostnamecache[dhcpd_lease[j][1]] = dhcpd_lease[j][0].split(' ').splice(0,1);
}
}
for (var i = 0 ; i <= MAX_BRIDGE_ID; i++) {
var j = (i == 0) ? '' : i.toString();
if ((nvram['lan'+j+'_ipaddr'] != null) && (nvram['lan'+j+'_netmask'] != null) && (nvram['lan'+j+'_ipaddr'] != '') && (nvram['lan'+j+'_netmask'] != ''))
hostnamecache[getNetworkAddress(nvram['lan'+j+'_ipaddr'], nvram['lan'+j+'_netmask'])] = 'LAN'+i;
}
}
