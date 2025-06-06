// Configuration
const API_BASE = window.location.origin;
let currentSessionId = null;
let uploadMode = "folder_path"; // Changed to folder path mode
let scanInterval = null;

// Enhanced Matrix rain effect (keeping your existing animation)
function createMatrixRain() {
  const matrixBg = document.getElementById("matrixBg");
  const chars =
    "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
  const columns = Math.floor(window.innerWidth / 20);
  const streams = [];

  for (let i = 0; i < columns; i++) {
    streams[i] = {
      chars: [],
      active: Math.random() > 0.7,
      nextChar: Math.random() * 100,
    };
  }

  function createMatrixColumn(columnIndex) {
    const stream = streams[columnIndex];
    if (!stream.active) {
      if (Math.random() < 0.005) {
        stream.active = true;
        stream.nextChar = 0;
      }
      return;
    }

    if (stream.nextChar <= 0) {
      const char = document.createElement("div");
      char.className = "matrix-char";
      char.textContent = chars[Math.floor(Math.random() * chars.length)];
      char.style.left = columnIndex * 20 + "px";
      char.style.top = "-20px";
      char.style.position = "absolute";
      char.style.color = Math.random() > 0.95 ? "#ffffff" : "#00ff88";
      char.style.fontSize = Math.random() * 6 + 12 + "px";
      char.style.fontFamily = "Courier New, monospace";
      char.style.fontWeight = Math.random() > 0.7 ? "bold" : "normal";
      char.style.textShadow = "0 0 5px currentColor";
      char.style.zIndex = "-1";
      char.style.opacity = "0.8";
      char.style.animation = `matrix-fall ${
        Math.random() * 3 + 2
      }s linear forwards`;

      matrixBg.appendChild(char);
      stream.chars.push(char);

      stream.chars.forEach((existingChar, index) => {
        const opacity = Math.max(0, 0.8 - index * 0.1);
        existingChar.style.opacity = opacity;
        if (opacity <= 0) {
          existingChar.remove();
          stream.chars.splice(index, 1);
        }
      });

      setTimeout(() => {
        if (char.parentNode) {
          char.remove();
        }
        const charIndex = stream.chars.indexOf(char);
        if (charIndex > -1) {
          stream.chars.splice(charIndex, 1);
        }
      }, 5000);

      stream.nextChar = Math.random() * 10 + 5;

      if (Math.random() < 0.01) {
        stream.active = false;
      }
    } else {
      stream.nextChar--;
    }
  }

  function animate() {
    for (let i = 0; i < columns; i++) {
      if (Math.random() < 0.8) {
        createMatrixColumn(i);
      }
    }
    requestAnimationFrame(animate);
  }

  animate();

  window.addEventListener("resize", () => {
    const newColumns = Math.floor(window.innerWidth / 20);
    if (newColumns !== columns) {
      matrixBg.innerHTML = "";
      createMatrixRain();
    }
  });
}

// DOM elements
const scanArea = document.getElementById("scanArea");
const scanButton = document.getElementById("scanButton");
const resultsArea = document.getElementById("resultsArea");
const loading = document.getElementById("loading");
const loadingText = document.getElementById("loadingText");
const progressBar = document.getElementById("progressBar");
const progressFill = document.getElementById("progressFill");
const vtApiKey = document.getElementById("vtApiKey");

// Analysis level selection
document.querySelectorAll(".option-card").forEach((card) => {
  card.addEventListener("click", function () {
    document
      .querySelectorAll(".option-card")
      .forEach((c) => c.classList.remove("selected"));
    this.classList.add("selected");
  });
});

// Setup In-Place Scanning Interface
function setupInPlaceScanning() {
  // Replace the upload interface with folder path input
  scanArea.innerHTML = `
    <div style="font-size: 3rem; margin-bottom: 15px;">📁</div>
    <div style="font-size: 1.2rem; margin-bottom: 10px;">Enter folder path to scan</div>
    <div style="color: #888; font-size: 0.9rem; margin-bottom: 15px;">Files will be scanned in their original location (safer!)</div>
    
    <input type="text" id="folderPath" placeholder="C:\\Users\\YourName\\Pictures" 
           style="width: 80%; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid rgba(0,255,136,0.3); border-radius: 5px; color: #fff; font-size: 0.9rem; margin-bottom: 15px;">
    
    <div style="display: flex; gap: 10px; justify-content: center; margin-bottom: 15px;">
        <button id="browseFolderBtn" class="upload-option-btn">📁 Browse Examples</button>
        <button id="validatePathBtn" class="upload-option-btn">✅ Validate Path</button>
    </div>
    
    <div id="pathValidation" style="margin-top: 10px; font-size: 0.9rem;"></div>
  `;
  
  // Update the upload options to show scanning info
  const uploadOptions = document.querySelector('.upload-options');
  if (uploadOptions) {
    uploadOptions.innerHTML = `
      <div style="text-align: center; color: #00ff88; font-size: 0.9rem;">
        <div>🔒 <strong>Safe In-Place Scanning</strong></div>
        <div style="color: #888; font-size: 0.8rem; margin-top: 5px;">No files copied • System directories blocked • Original location preserved</div>
      </div>
    `;
  }
  
  // Add event listeners
  document.getElementById('browseFolderBtn').addEventListener('click', showFolderExamples);
  document.getElementById('validatePathBtn').addEventListener('click', validateFolderPath);
  document.getElementById('folderPath').addEventListener('input', clearValidation);
  document.getElementById('folderPath').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      validateFolderPath();
    }
  });
}

function showFolderExamples() {
  const folderPath = document.getElementById('folderPath');
  const examples = [
    'C:\\Users\\' + (window.navigator.userAgent.includes('Windows') ? 'YourName' : 'YourName') + '\\Pictures',
    'C:\\Users\\' + (window.navigator.userAgent.includes('Windows') ? 'YourName' : 'YourName') + '\\Downloads',
    'C:\\Users\\' + (window.navigator.userAgent.includes('Windows') ? 'YourName' : 'YourName') + '\\Desktop',
    'D:\\Photos',
    'E:\\Images',
    'C:\\Temp\\ImageTest'
  ];
  
  const randomExample = examples[Math.floor(Math.random() * examples.length)];
  folderPath.value = randomExample;
  folderPath.focus();
  
  // Show a tooltip with more examples
  const validationDiv = document.getElementById('pathValidation');
  validationDiv.innerHTML = `
    <div style="color: #888; font-size: 0.8rem;">
      <strong>Example paths:</strong><br>
      • C:\\Users\\[Username]\\Pictures<br>
      • C:\\Users\\[Username]\\Downloads<br>
      • D:\\Photos or E:\\Images<br>
      <span style="color: #ffaa00;">Click "Validate Path" when ready</span>
    </div>
  `;
}

async function validateFolderPath() {
  const folderPath = document.getElementById('folderPath').value.trim();
  const validationDiv = document.getElementById('pathValidation');
  
  if (!folderPath) {
    validationDiv.innerHTML = '<div style="color: #ff4444;">❌ Please enter a folder path</div>';
    return;
  }
  
  validationDiv.innerHTML = '<div style="color: #ffaa00;">🔍 Validating path...</div>';
  
  try {
    const response = await fetch(`${API_BASE}/api/validate-path`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        folder_path: folderPath
      })
    });
    
    const result = await response.json();
    
    if (result.is_safe) {
      validationDiv.innerHTML = `<div style="color: #00ff88;">✅ ${result.message}</div>`;
      scanButton.disabled = false;
      scanButton.textContent = '🔍 Start Safe Scan';
    } else {
      validationDiv.innerHTML = `<div style="color: #ff4444;">❌ ${result.message}</div>`;
      scanButton.disabled = true;
      scanButton.textContent = '🔍 Start Analysis';
    }
    
  } catch (error) {
    validationDiv.innerHTML = `<div style="color: #ff4444;">❌ Error validating path: ${error.message}</div>`;
    scanButton.disabled = true;
  }
}

function clearValidation() {
  const validationDiv = document.getElementById('pathValidation');
  validationDiv.innerHTML = '';
  scanButton.disabled = true;
  scanButton.textContent = '🔍 Start Analysis';
}

// Updated scan function for in-place scanning
async function startInPlaceScan() {
  const folderPath = document.getElementById('folderPath').value.trim();
  const selectedLevel = document.querySelector('.option-card.selected').dataset.level;
  const vtApiKeyValue = vtApiKey.value.trim();
  
  if (!folderPath) {
    alert('Please enter a folder path and validate it first');
    return;
  }
  
  try {
    loading.style.display = 'block';
    progressBar.style.display = 'block';
    scanButton.disabled = true;
    resultsArea.innerHTML = '';
    
    const response = await fetch(`${API_BASE}/api/scan-folder`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        folder_path: folderPath,
        analysis_level: selectedLevel,
        vt_api_key: vtApiKeyValue
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Scan failed');
    }
    
    const result = await response.json();
    currentSessionId = result.session_id;
    
    // Show scan started message
    resultsArea.innerHTML = `
      <div style="text-align: center; color: #00ff88; margin: 20px 0;">
        <div style="font-size: 1.5rem; margin-bottom: 10px;">🔍</div>
        <div><strong>Safe In-Place Scan Started</strong></div>
        <div style="color: #888; font-size: 0.9rem; margin-top: 5px;">Scanning: ${folderPath}</div>
        <div style="color: #888; font-size: 0.9rem;">Level: ${selectedLevel.toUpperCase()}</div>
      </div>
    `;
    
    // Start polling for progress
    pollScanProgress();
    
  } catch (error) {
    console.error('Scan error:', error);
    loading.style.display = 'none';
    progressBar.style.display = 'none';
    scanButton.disabled = false;
    
    resultsArea.innerHTML = `
      <div style="text-align: center; color: #ff4444; margin-top: 50px;">
        <div style="font-size: 2rem; margin-bottom: 10px;">❌</div>
        <div>Scan failed: ${error.message}</div>
      </div>
    `;
  }
}

// Update scan button event listener
scanButton.addEventListener('click', startInPlaceScan);

// Keep your existing polling, display, and stats functions
async function pollScanProgress() {
  if (!currentSessionId) return;

  try {
    const response = await fetch(`${API_BASE}/api/status/${currentSessionId}`);
    const status = await response.json();

    if (!response.ok) {
      throw new Error(status.error || 'Status check failed');
    }

    // Update progress
    progressFill.style.width = status.progress + '%';
    
    // Update loading text based on status
    if (status.status === 'finding_files') {
      loadingText.textContent = 'Finding image files...';
    } else if (status.current_file) {
      loadingText.textContent = `Analyzing: ${status.current_file}`;
    } else {
      loadingText.textContent = 'Processing files...';
    }

    // Display intermediate results
    if (status.results && status.results.length > 0) {
      displayResults(status.results, false);
    }

    if (status.status === 'completed') {
      completeScan(status);
    } else if (status.status === 'error') {
      throw new Error(status.error || 'Scan failed on server');
    } else {
      // Continue polling
      setTimeout(pollScanProgress, 1000);
    }
  } catch (error) {
    console.error('Progress polling error:', error);
    loading.style.display = 'none';
    progressBar.style.display = 'none';
    scanButton.disabled = false;

    resultsArea.innerHTML = `
      <div style="text-align: center; color: #ff4444; margin-top: 50px;">
        <div style="font-size: 2rem; margin-bottom: 10px;">❌</div>
        <div>Error checking scan progress: ${error.message}</div>
      </div>
    `;
  }
}

function completeScan(status) {
  loading.style.display = 'none';
  progressBar.style.display = 'none';
  scanButton.disabled = false;

  displayResults(status.results, true);
  updateStats(status.results);

  // No cleanup needed for in-place scanning (no files to delete)
  currentSessionId = null;
}

function displayResults(results, isComplete) {
  const resultsHtml = results
    .map((result, index) => {
      const statusClass =
        {
          clean: "clean-item",
          threats: "threat-item",
          warnings: "warning-item",
          error: "error-item",
        }[result.status] || "error-item";

      const statusIcon =
        {
          clean: "✅",
          threats: "⚠️",
          warnings: "🔶",
          error: "❌",
        }[result.status] || "❌";

      let detailsHtml = "";

      if (result.status === "threats" && result.threats) {
        const threatsHtml = result.threats
          .slice(0, 3)
          .map(
            (threat) => `
              <li><span class="threat-level ${threat.level}">${threat.level}</span> <strong>${threat.type}</strong>: ${threat.description}</li>
            `
          )
          .join("");

        const moreThreats =
          result.threats.length > 3
            ? `<li style="color: #888;">... and ${
                result.threats.length - 3
              } more threats</li>`
            : "";

        detailsHtml = `
          <div class="threat-details">
            <strong>Threats Detected:</strong>
            <ul>${threatsHtml}${moreThreats}</ul>
            ${result.file_path ? `<div style="font-size: 0.8rem; color: #888; margin-top: 5px;">Path: ${result.file_path}</div>` : ''}
          </div>
        `;
      } else if (result.status === "warnings" && result.warnings) {
        const warningsHtml = result.warnings
          .slice(0, 2)
          .map(
            (warning) => `
              <li><span class="threat-level ${warning.level}">${warning.level}</span> ${warning.description}</li>
            `
          )
          .join("");

        const moreWarnings =
          result.warnings.length > 2
            ? `<li style="color: #888;">... and ${
                result.warnings.length - 2
              } more warnings</li>`
            : "";

        detailsHtml = `
          <div class="threat-details">
            <strong>Warnings:</strong>
            <ul>${warningsHtml}${moreWarnings}</ul>
            ${result.file_path ? `<div style="font-size: 0.8rem; color: #888; margin-top: 5px;">Path: ${result.file_path}</div>` : ''}
          </div>
        `;
      } else if (result.status === "error") {
        detailsHtml = `
          <div class="threat-details">
            <strong>Error:</strong> ${result.error || "Unknown error occurred"}
            ${result.file_path ? `<div style="font-size: 0.8rem; color: #888; margin-top: 5px;">Path: ${result.file_path}</div>` : ''}
          </div>
        `;
      } else if (result.status === "clean") {
        detailsHtml = `
          <div class="threat-details">
            <strong>File Analysis:</strong> No threats detected
            ${result.file_size ? `<br><strong>Size:</strong> ${(result.file_size / 1024).toFixed(1)} KB` : ""}
            ${result.file_path ? `<div style="font-size: 0.8rem; color: #888; margin-top: 5px;">Path: ${result.file_path}</div>` : ''}
          </div>
        `;
      }

      return `
        <div class="${statusClass}">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
            <strong>${statusIcon} ${result.filename}</strong>
            <span style="font-size: 0.8rem; color: #888;">${
              result.timestamp ? new Date(result.timestamp).toLocaleTimeString() : ""
            }</span>
          </div>
          ${detailsHtml}
        </div>
      `;
    })
    .join("");

  const statusText = isComplete
    ? `<div style="text-align: center; color: #00ff88; margin-bottom: 15px; font-weight: bold;">✅ Safe Scan Complete</div>`
    : `<div style="text-align: center; color: #ffaa00; margin-bottom: 15px; font-weight: bold;">🔄 Safe Scan in Progress</div>`;

  resultsArea.innerHTML = statusText + resultsHtml;
}

function updateStats(results) {
  const total = results.length;
  const threats = results.filter((r) => r.status === "threats").length;
  const clean = results.filter((r) => r.status === "clean").length;
  const detectionRate = total > 0 ? ((threats / total) * 100).toFixed(1) : 0;

  // Get current stats
  const currentTotal = parseInt(document.getElementById("totalScans").textContent) || 0;
  const currentThreats = parseInt(document.getElementById("threatsFound").textContent) || 0;
  const currentClean = parseInt(document.getElementById("cleanFiles").textContent) || 0;

  // Update with new totals
  animateNumber("totalScans", currentTotal + total);
  animateNumber("threatsFound", currentThreats + threats);
  animateNumber("cleanFiles", currentClean + clean);
  animateText("detectionRate", `${detectionRate}%`);
}

function animateNumber(elementId, targetValue) {
  const element = document.getElementById(elementId);
  const startValue = parseInt(element.textContent) || 0;
  const duration = 1000;
  const startTime = Date.now();

  function update() {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const currentValue = Math.floor(
      startValue + (targetValue - startValue) * progress
    );
    element.textContent = currentValue;

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

function animateText(elementId, targetText) {
  setTimeout(() => {
    document.getElementById(elementId).textContent = targetText;
  }, 500);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
  setupInPlaceScanning();
  createMatrixRain();
});

// Initialize immediately as well
setupInPlaceScanning();
createMatrixRain();