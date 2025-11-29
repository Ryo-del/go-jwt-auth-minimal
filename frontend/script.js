document.addEventListener('DOMContentLoaded', () => {
	const submitBtn = document.getElementById('submitBtn');
	const messageEl = document.getElementById('message');
	const usermailWrap = document.getElementById('usermailWrap');

	function showMessage(text, isError) {
		messageEl.textContent = text;
		messageEl.style.color = isError ? 'crimson' : 'green';
	}

	// Toggle email input visibility depending on selected action
	function updateFormMode() {
		const role = Array.from(document.getElementsByName('role')).find(r => r.checked)?.value;
		if (role === 'login') {
			usermailWrap.style.display = 'none';
		} else {
			usermailWrap.style.display = 'block';
		}
	}

	Array.from(document.getElementsByName('role')).forEach(r => r.addEventListener('change', updateFormMode));
	updateFormMode();

	submitBtn.addEventListener('click', async () => {
		const username = document.getElementById('username').value.trim();
		const usermail = document.getElementById('usermail') ? document.getElementById('usermail').value.trim() : '';
		const password = document.getElementById('password').value;
		const role = Array.from(document.getElementsByName('role')).find(r => r.checked)?.value || 'signin';

		if (!username || !password || (role === 'signin' && !usermail)) {
			showMessage('Please fill required fields', true);
			return;
		}

		const endpoint = role === 'signin' ? '/singin' : '/login';
		const url = `http://localhost:8080${endpoint}`;

		const params = new URLSearchParams();
		if (role === 'signin') {
			params.append('username', username);
			params.append('usermail', usermail);
			params.append('password', password);
		} else {
			// For login backend accepts username OR email in the `username` field
			params.append('username', username);
			params.append('password', password);
		}

		showMessage('Sending...', false);

		try {
			const res = await fetch(url, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: params.toString(),
				credentials: 'include'
			});

			const text = await res.text();
			if (res.ok) {
				showMessage(text || 'Success', false);
			} else {
				showMessage(`Error ${res.status}: ${text}`, true);
			}
		} catch (err) {
			showMessage('Network error: ' + err.message, true);
		}
	});
});

