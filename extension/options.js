document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get({ token: '' }, (data) => {
    document.getElementById('token').value = data.token;
  });
});

document.getElementById('save').addEventListener('click', () => {
  const token = document.getElementById('token').value.trim();
  chrome.storage.local.set({ token }, () => {
    const status = document.getElementById('status');
    status.textContent = 'Settings saved. Reconnecting...';
    setTimeout(() => {
      status.textContent = '';
    }, 3000);
  });
});
