const testConnection = async () => {
  try {
    const response = await fetch('https://glados.rocks');
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    console.log('Connection successful');
  } catch (error) {
    console.error('Connection failed:', error);
  }
};

const retryFetch = async (url, options, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);
      if (!response.ok) throw new Error('Network response was not ok');
      return response;
    } catch (error) {
      if (i === retries - 1) throw error;
    }
  }
};

const glados = async () => {
  const cookie = process.env.GLADOS;
  if (!cookie) return ['Checkin Error', 'No cookie provided'];
  try {
    const headers = {
      'cookie': cookie,
      'referer': 'https://glados.rocks/console/checkin',
      'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)',
    };
    const checkin = await retryFetch('https://glados.rocks/api/user/checkin', {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: '{"token":"glados.one"}',
    }).then((r) => r.json());
    const status = await retryFetch('https://glados.rocks/api/user/status', {
      method: 'GET',
      headers,
    }).then((r) => r.json());
    return [
      'Checkin OK',
      `${checkin.message}`,
      `Left Days ${Number(status.data.leftDays)}`,
    ];
  } catch (error) {
    return [
      'Checkin Error',
      `${error}`,
      `<${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}>`,
    ];
  }
};

const notify = async (contents) => {
  const token = process.env.NOTIFY;
  if (!token || !contents) return;
  await retryFetch(`https://www.pushplus.plus/send`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      token,
      title: contents[0],
      content: contents.join('<br>'),
      template: 'markdown',
    }),
  });
};

const main = async () => {
  try {
    await testConnection();
    const gladosResult = await glados();
    await notify(gladosResult);
  } catch (error) {
    console.error('Error in main:', error);
  } finally {
    process.exit(0);
  }
};

main();
