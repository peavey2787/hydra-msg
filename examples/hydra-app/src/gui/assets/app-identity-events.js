$('#generate-identity-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await handleIdentityForm(event.target, '/api/identity/generate', ['label', 'password', 'password_confirm'], 'Creating identity');
  } catch (error) {
    setOutput('#setup-output', error.message);
  }
});

$('#import-store-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await handleIdentityForm(
      event.target,
      '/api/identity/import-store',
      ['label', 'source_path', 'source_password', 'new_password', 'new_password_confirm', 'preserve_device_id'],
      'Importing identity store'
    );
  } catch (error) {
    setOutput('#setup-output', error.message);
  }
});

$('#import-backup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await handleIdentityForm(
      event.target,
      '/api/identity/import-backup',
      ['label', 'backup_path', 'backup_password', 'identity_password', 'identity_password_confirm', 'preserve_device_id'],
      'Importing recovery backup'
    );
  } catch (error) {
    setOutput('#setup-output', error.message);
  }
});

