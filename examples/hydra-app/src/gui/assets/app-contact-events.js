$('#refresh').addEventListener('click', () => refreshState().catch((error) => alert(error.message)));
$('#contact-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  try {
    const result = await api('/api/contacts/review', {
      method: 'POST',
      body: formBody({
        alias: form.get('alias'),
        public_key_hex: form.get('public_key_hex'),
        qr_payload: form.get('qr_payload'),
      }),
    });
    renderContactReview(result);
  } catch (error) {
    setOutput('#contact-review', error.message);
  }
});

$('#trust-contact').addEventListener('click', async () => {
  if (!pendingContactReview) return;
  try {
    const result = await api('/api/contacts/trust', {
      method: 'POST',
      body: formBody({
        alias: pendingContactReview.alias,
        public_key_hex: pendingContactReview.public_key_hex,
        qr_payload: pendingContactReview.qr_payload,
        confirm_safety: 'true',
        accept_key_change: 'false',
      }),
    });
    setOutput('#contact-review', result.message);
    pendingContactReview = null;
    $('#trust-contact').disabled = true;
    $('#accept-contact-key-change').disabled = true;
    $('#contact-form').reset();
    await refreshState();
  } catch (error) {
    setOutput('#contact-review', error.message);
  }
});

$('#accept-contact-key-change').addEventListener('click', async () => {
  if (!pendingContactReview || !pendingContactReview.key_change) return;
  try {
    const result = await api('/api/contacts/trust', {
      method: 'POST',
      body: formBody({
        alias: pendingContactReview.alias,
        public_key_hex: pendingContactReview.public_key_hex,
        qr_payload: pendingContactReview.qr_payload,
        confirm_safety: 'true',
        accept_key_change: 'true',
      }),
    });
    setOutput('#contact-review', result.message);
    pendingContactReview = null;
    $('#trust-contact').disabled = true;
    $('#accept-contact-key-change').disabled = true;
    $('#contact-form').reset();
    await refreshState();
  } catch (error) {
    setOutput('#contact-review', error.message);
  }
});

$('#generate-my-contact-card').addEventListener('click', async () => {
  try {
    const result = await api('/api/contacts/my-card', { method: 'POST' });
    renderMyContactCard(result.card);
    setStatus(result.message);
  } catch (error) {
    setOutput('#my-contact-card', error.message);
  }
});
