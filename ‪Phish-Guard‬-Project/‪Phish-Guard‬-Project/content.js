console.log('The email detection extension is now active!');
let previousEmailId = null; 

function isEmailBodyVisible() {
    const selectors = ['.a3s.aiL', '.a3s.aXjCH', '.a3s'];

    // Check for the email body in the main DOM
    for (let selector of selectors) {
        const element = document.querySelector(selector);
        if (element) {
            return true;
        }
    }

    // Check for the email body inside an iframe
    const iframe = document.querySelector('iframe');
    if (iframe) {
        try {
            const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;

            if (!iframeDoc) {
                console.warn('Iframe document is not accessible.');
                return false;
            }

            for (let selector of selectors) {
                const iframeElement = iframeDoc.querySelector(selector);
                if (iframeElement) {
                    return true;
                }
            }
        } catch (error) {
            // Ignore errors related to iframe access
        }
    }
    return false;
}
    
function getDetails() {
    // Locate the <div> element containing the unique message ID
    const emailIdElement = document.querySelector('div.adn.ads[data-legacy-message-id]'); // Selects the <div> with the unique message ID

    // Extract other email details
    const emailSubject = document.querySelector('h2.hP'); // Subject
    const emailSender = document.querySelector('span.gD'); // Sender
    const emailBody = document.querySelector('.a3s.aiL, .a3s.aXjCH, .a3s'); // Body

    if (emailIdElement && emailSubject && emailSender && emailBody) {
        return {
            id: emailIdElement.getAttribute('data-legacy-message-id'), // Extract the unique message ID
            subject: emailSubject.textContent.trim(),
            sender: {
                name: emailSender.textContent.trim(),
                email: emailSender.getAttribute('email'),
            },
            body: emailBody.innerText.trim(),
        };
    }

    return null; // Return null if required details are not found
}

function getSenderDomain() {
    // Extract sender's domain from the email address
    const emailDetails = this.getDetails();
    if (!emailDetails || !emailDetails.sender || !emailDetails.sender.email) {
        return null;
    }
    return emailDetails.sender.email.split('@')[1];
}

function getLinks() {
    // Extract all links from the email body
    const emailBody = document.querySelector('.a3s.aiL, .a3s.aXjCH, .a3s');
    if (!emailBody) return [];

    const emailContent = emailBody.innerText || ''; // Email body text
    const linksFromRegex = findLinksInText(emailContent); // Links found using regex
    const linksFromElements = Array.from(emailBody.querySelectorAll('a'))
        .map(link => link.href)
        .filter(href => href && isValidUrl(href)); // Links from <a> elements

    // Combine links from both sources and remove duplicates
    return Array.from(new Set([...linksFromRegex, ...linksFromElements]));
}

function findLinksInText(content) {
    // Find URLs in the text using regex
    const regex = /(?:https?:\/\/|www\.)[^\s]+/g;
    const links = content.match(regex) || [];
    return links.filter(isValidUrl); // Filter only valid URLs
}

function isValidUrl(url) {
    // Check if the URL is valid and uses http/https
    try {
        const parsedUrl = new URL(url);
        return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
    } catch (error) {
        return false;
    }
}

function getAttachments() {
    // Retrieve information about email attachments
    const attachmentElements = document.querySelectorAll('.aQy');
    if (!attachmentElements.length) {
        return [];
    }

    // Map attachment elements to objects with name and link
    return Array.from(attachmentElements).map(element => ({
        name: element.getAttribute('aria-label') || 'Unknown',
        link: element.querySelector('a')?.href || 'No download link available',
    }));
}

async function calculateSuspicionScore() {
    let score = 0;

    const weights = {
        phishingContent: 40, 
        suspiciousLinks: 30, 
        untrustedSender: 20, 
        suspiciousAttachments: 10, 
    };

    try {
        // Check for phishing content
        if (isContentPhishing()) {
            score += weights.phishingContent;
        }

        // Check for suspicious links
        if (await hasSuspiciousLinks()) {
            score += weights.suspiciousLinks;
        }

        // Check if sender is trusted
        if (!(await isSenderTrusted())) {
            console.warn('Sender is not trusted.');
            score += weights.untrustedSender;
        }

        // Check for suspicious attachments
        const attachments = getAttachments();
        const suspiciousAttachmentTypes = ['.exe', '.js', '.bat', '.vbs'];
        if (attachments.some(attachment => suspiciousAttachmentTypes.some(type => attachment.name.endsWith(type)))) {
            score += weights.suspiciousAttachments;
        }

        // Return the final score, capped at 100
        return Math.min(score, 100);
    } catch (error) {
        console.log('Error calculating suspicion score:', error.message);
        return 0; // Default score if an error occurs
    }
}


function showSecurityReport(score, findings) {
    const reportBox = document.createElement('div');
    reportBox.id = 'security-report';
    reportBox.style.cssText = `
        position: fixed;
        top: 20%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 350px;
        padding: 20px;
        background-color: #1e1e2e;
        color: white;
        font-family: Arial, sans-serif;
        border: 3px solid ${score >= 70 ? '#ff4d4d' : '#ffcc00'}; /* Red for high risk, yellow for medium */
        border-radius: 10px;
        box-shadow: 0 5px 10px rgba(0, 0, 0, 0.3);
        z-index: 9999;
    `;

    reportBox.innerHTML = `
        <h2 style="text-align: center; margin-bottom: 10px;">🛡️ Email Security Report</h2>
        <div style="margin-bottom: 15px; text-align: center;">
            <strong>Risk Score:</strong> ${score}/100
            <div style="width: 100%; background: #444; height: 10px; border-radius: 5px; margin-top: 5px;">
                <div style="width: ${score}%; background: ${
                    score >= 70 ? '#ff4d4d' : '#ffcc00'
                }; height: 10px; border-radius: 5px;"></div>
            </div>
        </div>
        <ul style="list-style-type: none; padding: 0;">
            ${findings.map(finding => `<li style="margin: 5px 0;">${finding}</li>`).join('')}
        </ul>
        <button style="margin-top: 15px; padding: 10px; background-color: #ff4d4d; border: none; color: white; cursor: pointer; border-radius: 5px; width: 100%;">Close</button>
    `;

    reportBox.querySelector('button').addEventListener('click', () => {
        document.body.removeChild(reportBox);
    });

    document.body.appendChild(reportBox);
}



function showSafeEmailAlert(score, findings) {
    const alertBox = document.createElement('div');
    alertBox.id = 'safe-email-alert';
    alertBox.style.cssText = `
        position: fixed;
        top: 20%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 400px;
        padding: 20px;
        background-color: #1e1e2e;
        color: white;
        font-family: Arial, sans-serif;
        border: 3px solid #4caf50; /* Green border for safe emails */
        border-radius: 10px;
        box-shadow: 0 5px 10px rgba(0, 0, 0, 0.3);
        z-index: 9999;
    `;

    alertBox.innerHTML = `
        <h2 style="text-align: center; margin-bottom: 10px;">✅ Safe Email Report</h2>
        <div style="margin-bottom: 15px; text-align: center;">
            <strong>Risk Score:</strong> ${score}/100
            <div style="width: 100%; background: #444; height: 10px; border-radius: 5px; margin-top: 5px;">
                <div style="width: ${score}%; background: #4caf50; height: 10px; border-radius: 5px;"></div>
            </div>
        </div>
        <ul style="list-style-type: none; padding: 0;">
            ${findings.map(finding => `<li style="margin: 5px 0;">${finding}</li>`).join('')}
        </ul>
    `;

    const closeButton = document.createElement('button');
    closeButton.textContent = "Close";
    closeButton.style.cssText = `
        margin-top: 15px;
        padding: 10px;
        background-color: #ff4d4d;
        border: none;
        color: white;
        cursor: pointer;
        border-radius: 5px;
        width: 100%;
    `;
    closeButton.addEventListener('click', () => {
        document.body.removeChild(alertBox);
    });

    
    const reportButton = document.createElement('button');
    reportButton.textContent = "If you think this email is suspicious, click here to report";
    reportButton.style.cssText = `
        margin-top: 10px;
        padding: 10px;
        background-color: #ff9800;
        color: white;
        border: none;
        cursor: pointer;
        border-radius: 5px;
        text-align: center;
        width: 100%;
    `;
    reportButton.addEventListener('click', () => {
        alert("Thank you! Your report has been received. We will review it shortly.");
        console.log("Report submitted with the following findings:", findings);
        document.body.removeChild(alertBox); 
    });

    alertBox.appendChild(closeButton);
    alertBox.appendChild(reportButton);

    document.body.appendChild(alertBox);
}





async function analyzeEmail(emailDetails) {
    if (!emailDetails) {
        return; // Exit if no email details are provided
    }
    try {
        const score = await calculateSuspicionScore(); // Calculate the suspicion score
         if (score >= 70) {
            const findings = [
                "❌ Suspicious links found",
                "❌ Sender is untrusted",
                "❌ Detected phishing keywords",
            ];
            showSecurityReport(score, findings);
        } else if (score >= 30) {
            const findings = [
                "⚠️ Sender is partially trusted",
                "⚠️ Links need review",
            ];
            showSecurityReport(score, findings);
        } else {
            const findings = [
                "✅ No suspicious links found",
                "✅ Sender is trusted",
                "✅ Email content is clean",
            ];
            showSafeEmailAlert(score, findings);
        }
    } catch (error) {
        console.error('Error analyzing email:', error.message);
    }
}

function isContentPhishing() {
    try {
        const emailBody = document.querySelector('.a3s.aiL, .a3s.aXjCH, .a3s')?.innerText; // Get the email body content
        if (!emailBody) {
            console.error('No email content found.');
            return false; // Return false if the email body is missing
        }

        // List of patterns indicating phishing content
        const phishingPatterns = [
            /verify your account/i,
            /urgent action required/i,
            /enter your password/i,
            /confirm your payment details/i,
            /limited time offer/i,
            /click here to secure your account/i,
            /your account has been compromised/i,
        ];

        // Check if any pattern matches the email content
        return phishingPatterns.some(pattern => pattern.test(emailBody));
    } catch (error) {
        console.error('Error checking for phishing content:', error.message);
        return false; // Return false if an error occurs
    }
}


    async function hasSuspiciousLinks() {
        const links = getLinks(); // Get all links from the email body
        if (links.length === 0) return false; // No links to check
    
    
        for (const link of links) {
            try {
                const isLinkSafe = await checkUrlWithGoogle(link); // Check each link with Google Safe Browsing API
                if (!isLinkSafe) {
                    return true; // Suspicious link found
                }
            } catch (error) {
                console.error('Error while checking link:', link, error.message);
            }
        }
    
        return false; // All links are safe
    }
    
    async function isSenderTrusted() {
        const domain = this.getSenderDomain(); // Get the sender's domain
        if (!domain) return false; // Domain not available
    
        return await this.checkDomainWithGoogle(domain); // Check the domain with Google Safe Browsing API
    }
    
    async function checkDomainWithGoogle(domain) {
        const apiKey = ''; // Replace with your Google API key
        const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    
        if (!domain || domain.trim() === '') {
            console.error('Domain is empty or invalid. Skipping API call.');
            return true; // Assume safe if domain is invalid
        }
    
        const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/; // Regex to validate domain format
        if (!domainRegex.test(domain)) {
            console.error(`Invalid domain format: ${domain}`);
            return true; // Assume safe if domain format is invalid
        }
    
        const urlToCheck = `http://${domain}`; // Construct a URL from the domain

        const requestBody = {
            client: {
                clientId: 'Phish-Guard',
                clientVersion: '1.0.0',
            },
            threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url: urlToCheck }],
            },
        };
    
        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody),
            });
    
            const result = await response.json(); // Parse the API response
    
            if (result.matches && result.matches.length > 0) {
                return false; // Domain is suspicious
            }
    
            return true; // Domain is safe
        } catch (error) {
            //console.error('Error while checking domain with Google Safe Browsing:', domain, error.message);
            return true; // Assume safe if an error occurs
        }
    }
    
    
    
    async function checkUrlWithGoogle(url) {
        const apiKey = ''; // Replace with your API key
        const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    
        try {
            const parsedUrl = new URL(url); // Validate the URL format
            if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
                console.error(`Invalid URL (unsupported protocol): ${url}`);
                return true; // Return true for unsupported protocols
            }
        } catch (error) {
            console.error(`Invalid URL format: ${url}`);
            return true; // Return true if the URL format is invalid
        }
    
        const requestBody = {
            client: {
                clientId: 'Phish-Guard',  
                clientVersion: '1.0.0',
            },
            threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url }],
            },
        };
    
        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody),
            });
    
            const result = await response.json(); // Parse the API response
    
            if (result.matches && result.matches.length > 0) {
                return false; // URL is suspicious
            }
    
            return true; // URL is safe
        } catch (error) {
            return true; // Assume the URL is safe if an error occurs
        }
    }
    

    async function processDomMutations(mutations) {
        if (isEmailBodyVisible()) { // Check if an email body is visible
            const currentEmailInfo = getDetails(); // Extract current email details
            
            // Ensure email details are valid and contain the necessary unique ID
            if (!currentEmailInfo || !currentEmailInfo.id || !currentEmailInfo.sender || !currentEmailInfo.sender.email) {
                return;
            }
            

            // Check if the current email is different from the previously processed email
            if (currentEmailInfo.id !== previousEmailId) {
                previousEmailId = currentEmailInfo.id; // Update the last processed email ID
                analyzeEmail(currentEmailInfo); // Analyze the email
            }

        }
    }
    
    // Initialize the system
    const domChangeObserver = new MutationObserver(processDomMutations); // Observe DOM changes for mutations
    const observerConfig = { childList: true, subtree: true };
    domChangeObserver.observe(document.body, observerConfig); // Start observing the DOM
    
