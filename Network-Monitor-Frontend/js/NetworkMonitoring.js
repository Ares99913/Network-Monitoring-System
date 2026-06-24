function pad(num) {
  return String(num).padStart(2, '0');
}
function formatTimestamp(date) {
  const day = pad(date.getDate());
  const month = pad(date.getMonth() + 1);
  const year = date.getFullYear();
  const hours = pad(date.getHours());
  const minutes = pad(date.getMinutes());
  const seconds = pad(date.getSeconds());
  return `${day}-${month}-${year}  ${hours}:${minutes}:${seconds}`;
}
function updateRefreshTime() {
  const el = document.getElementById('refreshTime');
  if (el) el.textContent = formatTimestamp(new Date());
}
function randomBetween(min, max, decimals) {
  const value = Math.random() * (max - min) + min;
  return value.toFixed(decimals);
}
function formatNumber(num) {
  return num.toLocaleString('en-US');
}
let dataSentMB = 0.43;
let dataReceivedMB = 0.17;
let packetsSent = 8190;
let packetsReceived = 2536;
function tickLiveStats() {
  const upload = randomBetween(0, 2.5, 2);
  const download = randomBetween(0, 6.5, 2);

  const uploadEl = document.getElementById('uploadSpeed');
  const downloadEl = document.getElementById('downloadSpeed');
  if (uploadEl) uploadEl.textContent = `${upload} Mbps`;
  if (downloadEl) downloadEl.textContent = `${download} Mbps`;

  dataSentMB += parseFloat(upload) * 0.05;
  dataReceivedMB += parseFloat(download) * 0.05;
  const dataSentEl = document.getElementById('dataSent');
  const dataReceivedEl = document.getElementById('dataReceived');
  const totalTrafficEl = document.getElementById('totalTraffic');
  if (dataSentEl) dataSentEl.textContent = `${dataSentMB.toFixed(2)} MB`;
  if (dataReceivedEl) dataReceivedEl.textContent = `${dataReceivedMB.toFixed(2)} MB`;
  if (totalTrafficEl) totalTrafficEl.textContent = `${((dataSentMB + dataReceivedMB) / 1024).toFixed(3)} GB`;
  packetsSent += Math.floor(Math.random() * 40);
  packetsReceived += Math.floor(Math.random() * 25);
  const packetsSentEl = document.getElementById('packetsSent');
  const packetsReceivedEl = document.getElementById('packetsReceived');
  if (packetsSentEl) packetsSentEl.textContent = formatNumber(packetsSent);
  if (packetsReceivedEl) packetsReceivedEl.textContent = formatNumber(packetsReceived);
  updateRefreshTime();
}
document.addEventListener('DOMContentLoaded', () => {
  updateRefreshTime();
  tickLiveStats();
  setInterval(tickLiveStats, 4000);
});