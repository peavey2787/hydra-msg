$('#create-direct-chat-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/chats/direct', {
      method: 'POST',
      body: formBody({ alias: getFormValue(event.target, 'alias') }),
    });
    selectedChatId = result.conversation_id;
    setOutput('#app-output', result.message);
    event.target.reset();
    await refreshState();
  } catch (error) {
    setOutput('#app-output', error.message);
  }
});

$('#create-group-chat-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/chats/group', {
      method: 'POST',
      body: formBody({
        kind: getFormValue(event.target, 'kind'),
        max_members: getFormValue(event.target, 'max_members'),
        list_policy: getFormValue(event.target, 'list_policy'),
      }),
    });
    selectedChatId = result.conversation_id;
    setOutput('#app-output', result.message);
    await refreshState();
  } catch (error) {
    setOutput('#app-output', error.message);
  }
});

$('#send-message-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!selectedChatId) {
    setOutput('#message-thread', 'Select a chat before sending.');
    return;
  }
  try {
    const result = await api('/api/chats/send', {
      method: 'POST',
      body: formBody({ conversation_id: selectedChatId, message: getFormValue(event.target, 'message') }),
    });
    setOutput('#app-output', result.message);
    event.target.reset();
    await refreshState();
  } catch (error) {
    setOutput('#message-thread', error.message);
  }
});

$('#receive-message-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!selectedChatId) {
    setOutput('#message-thread', 'Select a chat before storing a reviewed inbound message.');
    return;
  }
  try {
    const result = await api('/api/chats/receive-review', {
      method: 'POST',
      body: formBody({
        conversation_id: selectedChatId,
        sender_id_hex: getFormValue(event.target, 'sender_id_hex'),
        message: getFormValue(event.target, 'message'),
      }),
    });
    setOutput('#app-output', result.message);
    event.target.reset();
    await refreshState();
  } catch (error) {
    setOutput('#message-thread', error.message);
  }
});

$('#unlock-session-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = getFormValue(event.target, 'password');
  try {
    const result = await api('/api/identity/unlock-session', {
      method: 'POST',
      body: formBody({
        password,
        remember_me: getCheckboxValue(event.target, 'remember_me'),
        remember_duration: getFormValue(event.target, 'remember_duration') || 'session',
        remember_custom_seconds: getFormValue(event.target, 'remember_custom_seconds'),
      }),
    });
    setOutput('#app-output', `${result.message}; unlocked identities: ${result.session.unlocked_identity_count}`);
    event.target.reset();
    await refreshState();
  } catch (error) {
    setOutput('#app-output', error.message);
  }
});

$('#lock-all-identities').addEventListener('click', async () => {
  const result = await api('/api/identity/lock-all', { method: 'POST' });
  setOutput('#app-output', result.message);
  await refreshState();
});

$('#idle-timeout-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const seconds = getFormValue(event.target, 'seconds');
  try {
    const result = await api('/api/identity/idle-timeout', {
      method: 'POST',
      body: formBody({ seconds }),
    });
    setOutput('#app-output', result.message);
    await refreshState();
  } catch (error) {
    setOutput('#app-output', error.message);
  }

});

