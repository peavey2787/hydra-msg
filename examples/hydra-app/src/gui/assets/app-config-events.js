async function saveConfigField(key, value) {
  return api('/api/config/set', {
    method: 'POST',
    body: formBody({ key, value, advanced_confirm: 'true' }),
  });
}

async function saveConfigForm(form, outputSelector) {
  const output = $(outputSelector);
  output.textContent = 'Validating and saving settings...';
  const updates = [];
  for (const input of form.querySelectorAll('[data-key]')) {
    const value = input.type === 'checkbox' ? String(input.checked) : input.value;
    const result = await saveConfigField(input.dataset.key, value);
    updates.push(result.message);
  }
  setOutput(outputSelector, updates.join('\n'));
  await refreshState();
}

$('#advanced-chat-policy-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await saveConfigForm(event.target, '#config-output');
  } catch (error) {
    setOutput('#config-output', error.message);
  }
});

$('#advanced-rekey-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await saveConfigForm(event.target, '#config-output');
  } catch (error) {
    setOutput('#config-output', error.message);
  }
});


refreshState().catch((error) => {
  $('#setup-screen').classList.remove('hidden');
  $('#app-shell').classList.add('hidden');
  setOutput('#setup-output', error.message);
});
