$('#create-bootstrap-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const form = new FormData(event.target);
    const result = await api('/api/bootstrap/create', {
      method: 'POST',
      body: formBody({
        recipient_fingerprint: form.get('recipient_fingerprint'),
        ttl_seconds: form.get('ttl_seconds'),
      }),
    });
    setQrPayload(result.invite.join_code);
    renderBootstrapInvite(result.invite, '#bootstrap-review');
    setOutput('#app-output', result.message);
  } catch (error) {
    setOutput('#bootstrap-review', error.message);
  }
});

$('#accept-bootstrap-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const joinCode = getFormValue(event.target, 'join_code');
    const result = await api('/api/bootstrap/accept', {
      method: 'POST',
      body: formBody({ join_code: joinCode }),
    });
    renderBootstrapInvite(result.invite, '#bootstrap-review');
    setOutput('#app-output', result.message);
  } catch (error) {
    setOutput('#bootstrap-review', error.message);
  }
});

$('#copy-join-code').addEventListener('click', async () => {
  if (!currentJoinCode) {
    setOutput('#bootstrap-review', 'Generate an invite first.');
    return;
  }
  try {
    await navigator.clipboard.writeText(currentJoinCode);
    setOutput('#bootstrap-review', 'Join code copied to clipboard.');
  } catch (_error) {
    setOutput('#bootstrap-review', currentJoinCode);
  }
});

