// pages/api/report-scam.js
// INTENTIONALLY VULNERABLE TO SSRF FOR EDUCATIONAL PURPOSES

export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      error: 'Method not allowed',
      message: 'Please use POST method' 
    });
  }

  const { websiteUrl, description } = req.body;

  // Basic validation (intentionally weak - students can bypass)
  if (!websiteUrl) {
    return res.status(400).json({ 
      error: 'Missing required field',
      message: 'Website URL is required' 
    });
  }

  // Very weak URL validation (intentionally vulnerable)
  if (!websiteUrl.startsWith('http://') && !websiteUrl.startsWith('https://')) {
    return res.status(400).json({ 
      error: 'Invalid URL format',
      message: 'URL must start with http:// or https://' 
    });
  }

  try {
    // VULNERABILITY: Server-side request without proper validation
    // This allows attackers to make requests to internal services
    const response = await fetch(websiteUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'VolkDonations-ScamChecker/1.0',
        'Accept': 'text/html,application/json,*/*'
      },
      // Timeout to prevent hanging
      signal: AbortSignal.timeout(8000)
    });

    // Get content type
    const contentType = response.headers.get('content-type') || '';
    
    let pageData = {
      url: websiteUrl,
      status: response.status,
      statusText: response.statusText,
      contentType: contentType,
      headers: {}
    };

    // Capture interesting headers
    const interestingHeaders = ['server', 'x-powered-by', 'content-length', 'last-modified'];
    interestingHeaders.forEach(header => {
      const value = response.headers.get(header);
      if (value) {
        pageData.headers[header] = value;
      }
    });

    // Parse response based on content type
    if (contentType.includes('application/json')) {
      // If JSON, parse it
      const jsonData = await response.json();
      pageData.content = jsonData;
      pageData.preview = JSON.stringify(jsonData, null, 2).substring(0, 2000);
    } else {
      // If HTML or text, get the raw content
      const textContent = await response.text();
      pageData.fullContent = textContent;
      
      // Extract page title if HTML
      const titleMatch = textContent.match(/<title[^>]*>(.*?)<\/title>/i);
      if (titleMatch) {
        pageData.pageTitle = titleMatch[1].trim();
      }

      // Extract meta description if HTML
      const descMatch = textContent.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i);
      if (descMatch) {
        pageData.metaDescription = descMatch[1].trim();
      }

      // Provide preview (first 2000 characters)
      pageData.preview = textContent.substring(0, 2000);
      pageData.contentLength = textContent.length;
    }

    // Check if it's potentially a scam (basic heuristics)
    const urlLower = websiteUrl.toLowerCase();
    const isSuspicious = 
      urlLower.includes('volk') || 
      urlLower.includes('donation') || 
      (pageData.pageTitle && pageData.pageTitle.toLowerCase().includes('volk'));

    pageData.suspicious = isSuspicious;
    pageData.reason = isSuspicious 
      ? 'Website contains keywords related to Volk Donations' 
      : 'No immediate red flags detected';

    // Log the report (in production, save to database)
    console.log(`[SCAM REPORT] URL: ${websiteUrl}, Description: ${description || 'N/A'}`);

    return res.status(200).json({
      success: true,
      message: 'Website analyzed successfully',
      data: pageData,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    // Detailed error for debugging (intentionally verbose for SSRF exploitation)
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

// Export config for Vercel
export const config = {
  api: {
    bodyParser: {
      sizeLimit: '1mb',
    },
    responseLimit: '8mb',
  },
};
