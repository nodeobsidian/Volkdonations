//    /api/report-scam.js

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      error: 'Method not allowed',
      message: 'Please use POST method' 
    });
  }

  const { websiteUrl, description, method = 'GET', headers = {} } = req.body;

  if (!websiteUrl) {
    return res.status(400).json({ 
      error: 'Missing required field',
      message: 'Website URL is required' 
    });
  }

  if (!websiteUrl.startsWith('http://') && !websiteUrl.startsWith('https://')) {
    return res.status(400).json({ 
      error: 'Invalid URL format',
      message: 'URL must start with http:// or https://' 
    });
  }

  try {
    const fetchOptions = {
      method: method.toUpperCase(),
      headers: {
        'User-Agent': 'VolkDonations-ScamChecker/1.0',
        'Accept': 'text/html,application/json,*/*',
        ...headers
      },
      signal: AbortSignal.timeout(8000)
    };

    const response = await fetch(websiteUrl, fetchOptions);
    const contentType = response.headers.get('content-type') || '';
    
    let pageData = {
      url: websiteUrl,
      status: response.status,
      statusText: response.statusText,
      contentType: contentType,
      headers: {}
    };

    const interestingHeaders = ['server', 'x-powered-by', 'content-length', 'last-modified', 'set-cookie'];
    interestingHeaders.forEach(header => {
      const value = response.headers.get(header);
      if (value) {
        pageData.headers[header] = value;
      }
    });

    if (contentType.includes('application/json')) {
      const jsonData = await response.json();
      pageData.content = jsonData;
      pageData.preview = JSON.stringify(jsonData, null, 2).substring(0, 2000);
    } else {
      const textContent = await response.text();
      pageData.fullContent = textContent;
      
      const titleMatch = textContent.match(/<title[^>]*>(.*?)<\/title>/i);
      if (titleMatch) {
        pageData.pageTitle = titleMatch[1].trim();
      }

      const descMatch = textContent.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i);
      if (descMatch) {
        pageData.metaDescription = descMatch[1].trim();
      }

      pageData.preview = textContent.substring(0, 2000);
      pageData.contentLength = textContent.length;
    }

    const urlLower = websiteUrl.toLowerCase();
    const isOwnDomain = urlLower.includes('volkdonations.website');
    
    let isSuspicious = false;
    let reason = 'No immediate red flags detected';
    
    if (!isOwnDomain) {
      if (urlLower.includes('volk') || urlLower.includes('donation')) {
        isSuspicious = true;
        reason = 'Website contains keywords related to Volk Donations';
      } else if (pageData.pageTitle && pageData.pageTitle.toLowerCase().includes('volk')) {
        isSuspicious = true;
        reason = 'Page title references Volk Donations';
      }
    } else {
      reason = 'Official Volk Donations domain - verified legitimate';
    }

    pageData.suspicious = isSuspicious;
    pageData.reason = reason;
    pageData.verified = isOwnDomain;

    console.log(`[SCAM REPORT] URL: ${websiteUrl}, Method: ${method}, Description: ${description || 'N/A'}`);

    return res.status(200).json({
      success: true,
      message: 'Website analyzed successfully',
      data: pageData,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Failed to fetch website',
      message: error.message,
      details: {
        code: error.code,
        type: error.name,
        url: websiteUrl
      },
      hint: 'This could be a network error, timeout, or invalid URL'
    });
  }
}

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '1mb',
    },
    responseLimit: '8mb',
  },
};
