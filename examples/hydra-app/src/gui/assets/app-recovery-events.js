$('#export-recovery-backup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const result = await api('/api/recovery/export-backup', {
      method: 'POST',
      body: formBody({
        backup_path: getFormValue(form, 'backup_path'),
        identity_password: getFormValue(form, 'identity_password'),
        backup_password: getFormValue(form, 'backup_password'),
        include_conversations: getCheckboxValue(form, 'include_conversations'),
        allow_active_device_clone: getCheckboxValue(form, 'allow_active_device_clone'),
      }),
    });
    setOutput('#recovery-output', JSON.stringify(result, null, 2));
    form.reset();
    await refreshState();
  } catch (error) {
    setOutput('#recovery-output', error.message);
  }
});

$('#inspect-recovery-backup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const result = await api('/api/recovery/inspect-backup', {
      method: 'POST',
      body: formBody({
        backup_path: getFormValue(form, 'backup_path'),
        backup_password: getFormValue(form, 'backup_password'),
      }),
    });
    setOutput('#recovery-output', JSON.stringify(result, null, 2));
  } catch (error) {
    setOutput('#recovery-output', error.message);
  }
});

$('#export-signed-checkpoint-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const result = await api('/api/recovery/export-checkpoint', {
      method: 'POST',
      body: formBody({
        export_dir: getFormValue(form, 'export_dir'),
        identity_password: getFormValue(form, 'identity_password'),
      }),
    });
    setOutput('#recovery-output', JSON.stringify(result, null, 2));
    form.reset();
    await refreshState();
  } catch (error) {
    setOutput('#recovery-output', error.message);
  }
});

$('#check-signed-history-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const result = await api('/api/recovery/check-history', {
      method: 'POST',
      body: formBody({ checkpoint_paths: getFormValue(form, 'checkpoint_paths') }),
    });
    setOutput('#recovery-output', JSON.stringify(result, null, 2));
    await refreshState();
  } catch (error) {
    setOutput('#recovery-output', error.message);
  }
});
