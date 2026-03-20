// STEP 1: SETUP VARIABLES
function getAuthHeader() {
  const token = sessionStorage.getItem('authToken');
  return token ? { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' };
}

// This stores the current logged-in user (null = not logged in)
let currentUser = null;

// This is the key we use to save data in localStorage
const STORAGE_KEY = "ipt_demo_v1";

// This is our "database" - stored in browser's localStorage
window.db = {};

// STEP 2: LOAD DATA FROM STORAGE

// This runs when the page loads
// It loads saved data or creates default data
function loadFromStorage() {
  // Try to get saved data from localStorage
  const rawData = localStorage.getItem(STORAGE_KEY);

  if (rawData) {
    // If data exists, parse it from JSON string to object
    window.db = JSON.parse(rawData);
  } else {
    // If no data exists, create default data
    window.db = {
      // Default admin account
      accounts: [
        {
          firstName: "Admin",
          lastName: "User",
          email: "admin@example.com",
          password: "Password123!",
          role: "admin",
          verified: true,
        },
      ],
      // Default departments
      departments: [
        {
          id: 1,
          name: "Engineering",
          description: "Software development team",
        },
        { id: 2, name: "HR", description: "Human resources team" },
      ],
      // Empty lists for employees and requests
      employees: [],
      requests: [],
    };
    // Save the default data
    saveToStorage();
  }
}

// STEP 3: SAVE DATA TO STORAGE

// This saves our database to localStorage
function saveToStorage() {
  // Convert object to JSON string and save
  localStorage.setItem(STORAGE_KEY, JSON.stringify(window.db));
}

// STEP 4: NAVIGATION (ROUTING)

// Change the URL hash to navigate to a page
function navigateTo(hash) {
  window.location.hash = hash;
}

// This function runs when URL hash changes
// It shows/hides pages based on the URL
function handleRouting() {
  // Get the current hash (default to "#/" if none)
  let hash = window.location.hash || "#/";

  // Hide all pages first
  document.querySelectorAll(".page").forEach((page) => {
    page.classList.remove("active");
  });

  // Convert hash to page ID
  // Example: "#/login" becomes "login-page"
  const pageName = hash.replace("#/", "");
  const pageId = pageName + "-page";

  // Find the page element
  let page = document.getElementById(pageId);

  // If page not found, show home page
  if (!page) {
    page = document.getElementById("home-page");
  }

  // SECURITY: Check if user needs to be logged in
  const protectedPages = [
    "profile",
    "accounts",
    "employees",
    "department",
    "requests",
  ];

  if (!currentUser && protectedPages.includes(pageName)) {
    // Not logged in - redirect to login
    navigateTo("#/login");
    return;
  }

  // SECURITY: Check if user needs admin role
  const adminOnlyPages = ["accounts", "employees", "department"];

  if (
    currentUser &&
    currentUser.role !== "admin" &&
    adminOnlyPages.includes(pageName)
  ) {
    // Not admin - redirect to home
    navigateTo("#/");
    return;
  }

  // Show the page
  page.classList.add("active");

  // Call renderProfile() when navigating to profile page
  if (pageName === "profile") {
    renderProfile();
  }

  // Call render functions for admin pages
  if (pageName === "accounts") {
    renderAccountsList();
  }
  if (pageName === "department") {
    renderDepartmentsTable();
  }
  if (pageName === "employee") {
    renderEmployeesTable();
  }
  if (pageName === "requests") {
    renderRequestsTable();
  }
  
  // Display email on verify page
  if (pageName === "verify") {
    const verifyEmailDisplay = document.getElementById('verify-email-display');
    const unverifiedEmail = sessionStorage.getItem('unverified_email');
    if (verifyEmailDisplay && unverifiedEmail) {
      verifyEmailDisplay.innerText = unverifiedEmail;
    }
  }
}

// Listen for URL hash changes
window.addEventListener("hashchange", handleRouting);

// STEP 5: AUTHENTICATION STATE

// This updates the UI based on login state
function setAuthState(isLoggedIn, user = null) {
  // Store the current user
  currentUser = user;
  // Update body classes for CSS styling
  document.body.classList.toggle("authenticated", isLoggedIn);
  document.body.classList.toggle("not-authenticated", !isLoggedIn);

  // Add admin class if user is admin
  if (user && user.role === "admin") {
    document.body.classList.add("is-admin");
  } else {
    document.body.classList.remove("is-admin");
  }

  // Update navigation to show username
  const navUsername = document.getElementById("nav-username");
  if (navUsername && user) {
    navUsername.innerText = user.firstName;
  }

  // Update profile page with user data
  renderProfile();
}

// Render profile page with current user data from localStorage
function renderProfile() {
  if (!currentUser) return;

  const nameEl = document.getElementById("profile-name");
  const emailEl = document.getElementById("profile-email");
  const roleEl = document.getElementById("profile-role");

  if (nameEl) {
    nameEl.innerText = currentUser.firstName + " " + currentUser.lastName;
  }
  if (emailEl) {
    emailEl.innerText = currentUser.email;
  }
  if (roleEl) {
    // Capitalize first letter of role
    roleEl.innerText =
      currentUser.role.charAt(0).toUpperCase() + currentUser.role.slice(1);
  }
}

// Handle Edit Profile button click
function handleEditProfile() {
  alert(
    "Edit Profile functionality coming soon! User: " + currentUser.firstName,
  );
}

// Show the edit profile form
function showEditProfileForm() {
  if (!currentUser) return;

  // Populate the form with current user data
  document.getElementById("edit-firstname").value = currentUser.firstName;
  document.getElementById("edit-lastname").value = currentUser.lastName;
  document.getElementById("edit-email").value = currentUser.email;

  // Toggle visibility
  document.getElementById("profile-view").style.display = "none";
  document.getElementById("profile-edit").style.display = "block";
}

// Cancel editing and return to view mode
function cancelEditProfile() {
  document.getElementById("profile-view").style.display = "block";
  document.getElementById("profile-edit").style.display = "none";
}

// Save the edited profile
function saveProfile() {
  if (!currentUser) return;

  const newFirstName = document.getElementById("edit-firstname").value.trim();
  const newLastName = document.getElementById("edit-lastname").value.trim();

  // Validate inputs
  if (!newFirstName || !newLastName) {
    alert("First Name and Last Name are required");
    return;
  }

  // Update currentUser
  currentUser.firstName = newFirstName;
  currentUser.lastName = newLastName;

  // Update in database (window.db.accounts)
  const userIndex = window.db.accounts.findIndex(
    (account) => account.email === currentUser.email,
  );
  if (userIndex !== -1) {
    window.db.accounts[userIndex].firstName = newFirstName;
    window.db.accounts[userIndex].lastName = newLastName;
    saveToStorage();
  }

  // Update the UI
  renderProfile();
  cancelEditProfile();

  // Update nav username
  const navUsername = document.getElementById("nav-username");
  if (navUsername) {
    navUsername.innerText = newFirstName;
  }

  alert("Profile updated successfully!");
}

// STEP 6: LOGIN FUNCTION

async function handleLogin() {
  const email = document.getElementById("login-email").value;
  const password = document.getElementById("login-password").value;

  if (!email || !password) {
    alert("Please enter email and password");
    return;
  }
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: password })
    });

    const data = await response.json();
    if (response.ok) {
      sessionStorage.setItem('authToken', data.token);

      const user = {
        firstName: data.user.firstName || data.user.email,
        lastName: data.user.lastName || '',
        email: email,
        role: data.user.role,
        verified: true
      };
      setAuthState(true, user);
      navigateTo("#/profile");
      alert("Login successful! Welcome, " + user.firstName);
    } else {
      alert("Login failed: " + data.error);
    }
  } catch (err) {
    console.error('Login error:', err);
    alert("Network error. Is the backend running?");
  }
}

// STEP 7: REGISTER FUNCTION

async function handleRegister() {
  const firstName = document.getElementById("reg-firstname").value;
  const lastName = document.getElementById("reg-lastname").value;
  const email = document.getElementById("reg-email").value;
  const password = document.getElementById("reg-password").value;

  if (!firstName || !lastName || !email || !password) {
    alert("Please fill in all fields");
    return;
  }
  if (password.length < 6) {
    alert("Password must be at least 6 characters");
    return;
  }

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: password, firstName: firstName, lastName: lastName, role: 'user' })
    });

    const data = await response.json();

    if (response.ok) {
      // Store email for the verify page to display
      sessionStorage.setItem('unverified_email', email);
      alert("Registration successful! Please verify your email.");
      navigateTo("#/verify");
    } else {
      alert("Registration failed: " + data.error);
    }
  } catch (err) {
    console.error('Register error:', err);
    alert("Network error. Is the backend running?");
  }
}


// STEP 8: EMAIL VERIFICATION FUNCTION

function handleVerify() {
  const unverifiedEmail = sessionStorage.getItem('unverified_email');

  if (!unverifiedEmail) {
    alert("No pending verification found. Please register first.");
    navigateTo("#/register");
    return;
  }

  // Simulate verification (server already registered the user)
  sessionStorage.removeItem('unverified_email');
  justVerified = true;
  alert("Email verified! You can now login with email: " + unverifiedEmail);
  navigateTo("#/login");
}

// STEP 9: LOGOUT FUNCTION

function handleLogout() {
  // Clear the auth token
  localStorage.removeItem("auth_token");

  // Reset the UI state
  setAuthState(false, null);

  // Navigate to home
  navigateTo("#/");

  alert("You have been logged out");
}

// STEP 10: PAGE INITIALIZATION

// This runs when the page finishes loading
document.addEventListener("DOMContentLoaded", async function() {
  // Load CRUD data (requests, employees, departments) from localStorage
  loadFromStorage();

  const savedToken = sessionStorage.getItem('authToken');
  if (savedToken) {
    try {
      const response = await fetch('/api/profile', {
        headers: getAuthHeader()
      });

      if (response.ok) {
        const data = await response.json();
        const user = {
          firstName: data.user.firstName || data.user.email,
          lastName: data.user.lastName || '',
          email: data.user.email,
          role: data.user.role,
          verified: true
        };
        setAuthState(true, user);
      } else {
        // Token expired or invalid — clear it
        sessionStorage.removeItem('authToken');
      }
    } catch (err) {
      console.error('Session restore failed:', err);
      sessionStorage.removeItem('authToken');
    }
  }

  handleRouting();
  setupButtonHandlers();
});

// STEP 11: BUTTON HANDLERS

function setupButtonHandlers() {
  // Get Started button - goes to register page
  const getStartedBtn = document.querySelector(".getstarted-btn");
  if (getStartedBtn) {
    getStartedBtn.onclick = function () {
      navigateTo("#/register");
    };
  }

  // Login button
  const loginBtn = document.querySelector("#login-page .btn-outline-primary");
  if (loginBtn) {
    loginBtn.onclick = handleLogin;
  }

  // Register button
  const registerBtn = document.querySelector("#register-page .btn-success");
  if (registerBtn) {
    registerBtn.onclick = handleRegister;
  }

  // Verify button
  const verifyBtn = document.querySelector("#verify-page .btn-success");
  if (verifyBtn) {
    verifyBtn.onclick = handleVerify;
  }

  // Logout link in dropdown
  const logoutLink = document.querySelector(".dropdown-item[href='#logout']");
  if (logoutLink) {
    logoutLink.onclick = function (e) {
      e.preventDefault();
      handleLogout();
    };
  }

  // Accounts page buttons
  const addAccountBtn = document.querySelector(
    "#accounts-page .acc-head .btn-success",
  );
  if (addAccountBtn) {
    addAccountBtn.onclick = function () {
      showAccountForm();
    };
  }
  const saveAccountBtn = document.querySelector(".acct-cont .btn-primary");
  if (saveAccountBtn) {
    saveAccountBtn.onclick = saveAccount;
  }
  const cancelAccountBtn = document.querySelector(".acct-cont .btn-secondary");
  if (cancelAccountBtn) {
    cancelAccountBtn.onclick = hideAccountForm;
  }

  // Departments page button
  const addDeptBtn = document.querySelector("#department-page .btn-success");
  if (addDeptBtn) {
    addDeptBtn.onclick = addDepartment;
  }

  // Employees page buttons
  const addEmpBtn = document.querySelector(
    "#employee-page .emp-left .btn-success",
  );
  if (addEmpBtn) {
    addEmpBtn.onclick = function () {
      showEmployeeForm();
    };
  }
  const saveEmpBtn = document.querySelector(".adedemp .btn-outline-primary");
  if (saveEmpBtn) {
    saveEmpBtn.onclick = saveEmployee;
  }
  const cancelEmpBtn = document.querySelector(".adedemp .btn-light");
  if (cancelEmpBtn) {
    cancelEmpBtn.onclick = hideEmployeeForm;
  }

  // Requests page buttons
  const newRequestBtn = document.getElementById("new-request-btn");
  if (newRequestBtn) {
    newRequestBtn.onclick = function () {
      initRequestModal();
      const modal = new bootstrap.Modal(
        document.getElementById("requestModal"),
      );
      modal.show();
    };
  }
  const addItemBtn = document.getElementById("add-item-btn");
  if (addItemBtn) {
    addItemBtn.onclick = addRequestItem;
  }
  const submitRequestBtn = document.getElementById("submit-request-btn");
  if (submitRequestBtn) {
    submitRequestBtn.onclick = submitRequest;
  }

  // Navigation links
  setupNavigationLinks();
}

// STEP 12: NAVIGATION LINKS

function setupNavigationLinks() {
  // Login link in nav
  const loginLink = document.querySelector('.links a[href="#login"]');
  if (loginLink) {
    loginLink.onclick = function (e) {
      e.preventDefault();
      navigateTo("#/login");
    };
  }

  // Register link in nav
  const registerLink = document.querySelector('.links a[href="#register"]');
  if (registerLink) {
    registerLink.onclick = function (e) {
      e.preventDefault();
      navigateTo("#/register");
    };
  }

  // Dropdown menu links
  const dropdownLinks = document.querySelectorAll(".dropdown-item");
  dropdownLinks.forEach((link) => {
    const href = link.getAttribute("href");
    if (href && href.startsWith("#") && href !== "#logout") {
      link.onclick = function (e) {
        e.preventDefault();
        const page = href.replace("#", "");
        navigateTo("#/" + page);
      };
    }
  });
}

// HELPER FUNCTIONS (can be called from HTML onclick)

// Go to register page - can be used with onclick="goToRegister()"
function goToRegister() {
  navigateTo("#/register");
}
// Go to login page - can be used with onclick="goToLogin()"
function goToLogin() {
  navigateTo("#/login");
}

// ============================================
// ACCOUNTS MANAGEMENT
// ============================================

let editingAccountIndex = null;

// Render the accounts table
function renderAccountsList() {
  const tbody = document.querySelector("#accounts-page tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  window.db.accounts.forEach((account, index) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${account.firstName} ${account.lastName}</td>
      <td>${account.email}</td>
      <td>${account.role}</td>
      <td>${account.verified ? "✅" : "—"}</td>
      <td class="tb-btn-holder">
        <button class="btn btn-outline-primary btn-sm" onclick="editAccount(${index})">Edit</button>
        <button class="btn btn-outline-warning btn-sm" onclick="resetPassword(${index})">Reset PW</button>
        <button class="btn btn-outline-danger btn-sm" onclick="deleteAccount(${index})">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Show the account form (for add or edit)
function showAccountForm(index = null) {
  editingAccountIndex = index;
  const container = document.querySelector(".acct-cont");
  const formTitle = container.querySelector("div");

  if (index !== null) {
    // Edit mode - pre-fill form
    formTitle.textContent = "Edit Account";
    const account = window.db.accounts[index];
    document.getElementById("firstname").value = account.firstName;
    document.getElementById("lastname").value = account.lastName;
    document.getElementById("email").value = account.email;
    document.getElementById("password").value = "";
    document.getElementById("role").value = account.role;
    document.getElementById("verified").checked = account.verified;
  } else {
    // Add mode - clear form
    formTitle.textContent = "Add Account";
    document.getElementById("firstname").value = "";
    document.getElementById("lastname").value = "";
    document.getElementById("email").value = "";
    document.getElementById("password").value = "";
    document.getElementById("role").value = "user";
    document.getElementById("verified").checked = false;
  }
  container.style.display = "block";
}

// Hide the account form
function hideAccountForm() {
  document.querySelector(".acct-cont").style.display = "none";
  editingAccountIndex = null;
}

// Save account (add or update)
function saveAccount() {
  const firstName = document.getElementById("firstname").value.trim();
  const lastName = document.getElementById("lastname").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const role = document.getElementById("role").value;
  const verified = document.getElementById("verified").checked;

  // Validation
  if (!firstName || !lastName || !email || !role) {
    alert("Please fill in all required fields");
    return;
  }

  if (editingAccountIndex !== null) {
    // Update existing account
    const account = window.db.accounts[editingAccountIndex];
    account.firstName = firstName;
    account.lastName = lastName;
    account.email = email;
    account.role = role;
    account.verified = verified;
    if (password) account.password = password;
  } else {
    // Add new account
    if (!password) {
      alert("Password is required for new accounts");
      return;
    }
    if (window.db.accounts.some((a) => a.email === email)) {
      alert("Email already exists");
      return;
    }
    window.db.accounts.push({
      firstName,
      lastName,
      email,
      password,
      role,
      verified,
    });
  }

  saveToStorage();
  renderAccountsList();
  hideAccountForm();
  alert("Account saved successfully!");
}

// Edit account - opens form pre-filled
function editAccount(index) {
  showAccountForm(index);
}

// Reset password
function resetPassword(index) {
  const account = window.db.accounts[index];
  const newPassword = prompt(
    `Enter new password for ${account.email} (min 6 chars):`,
  );

  if (newPassword === null) return; // Cancelled

  if (newPassword.length < 6) {
    alert("Password must be at least 6 characters");
    return;
  }

  account.password = newPassword;
  saveToStorage();
  alert("Password reset successfully!");
}

// Delete account with self-deletion prevention
function deleteAccount(index) {
  const account = window.db.accounts[index];

  // Prevent self-deletion
  if (currentUser && account.email === currentUser.email) {
    alert("You cannot delete your own account!");
    return;
  }

  if (confirm(`Delete account "${account.email}"?`)) {
    window.db.accounts.splice(index, 1);
    saveToStorage();
    renderAccountsList();
    alert("Account deleted!");
  }
}

// ============================================
// DEPARTMENTS MANAGEMENT
// ============================================

// Render the departments table
function renderDepartmentsTable() {
  const tbody = document.querySelector("#department-page tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  window.db.departments.forEach((dept, index) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${dept.name}</td>
      <td>${dept.description}</td>
      <td>
        <button class="btn btn-outline-primary btn-sm" onclick="editDepartment(${index})">Edit</button>
        <button class="btn btn-outline-danger btn-sm" onclick="deleteDepartment(${index})">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Add department (not implemented)
function addDepartment() {
  alert("Not implemented");
}

// Edit department (not implemented)
function editDepartment(index) {
  alert("Not implemented");
}

// Delete department (not implemented)
function deleteDepartment(index) {
  alert("Not implemented");
}

// ============================================
// EMPLOYEES MANAGEMENT
// ============================================

let editingEmployeeIndex = null;

// Render the employees table
function renderEmployeesTable() {
  const tbody = document.querySelector("#employee-page tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  window.db.employees.forEach((emp, index) => {
    // Find user email by userId
    const user = window.db.accounts.find((a) => a.email === emp.userId);
    const userEmail = user ? user.email : "—";

    // Find department name by deptId
    const dept = window.db.departments.find((d) => d.id === emp.deptId);
    const deptName = dept ? dept.name : "—";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${emp.id}</td>
      <td>${userEmail}</td>
      <td>${emp.position}</td>
      <td>${deptName}</td>
      <td>
        <button class="btn btn-outline-primary btn-sm" onclick="editEmployee(${index})">Edit</button>
        <button class="btn btn-outline-danger btn-sm" onclick="deleteEmployee(${index})">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Populate department dropdown
function populateDepartmentDropdown() {
  const select = document.getElementById("department");
  if (!select) return;

  select.innerHTML = '<option value="">Select Department</option>';

  window.db.departments.forEach((dept) => {
    const option = document.createElement("option");
    option.value = dept.id;
    option.textContent = dept.name;
    select.appendChild(option);
  });
}

// Show employee form
function showEmployeeForm(index = null) {
  editingEmployeeIndex = index;
  const formContainer = document.querySelector(".adedemp");
  const formTitle = formContainer.querySelector(".addedit");

  populateDepartmentDropdown();

  if (index !== null) {
    // Edit mode
    formTitle.textContent = "Edit Employee";
    const emp = window.db.employees[index];
    document.getElementById("empid").value = emp.id;
    document.getElementById("emp-email").value = emp.userId;
    document.getElementById("position").value = emp.position;
    document.getElementById("department").value = emp.deptId;
    document.getElementById("date").value = emp.hireDate || "";
  } else {
    // Add mode - clear form
    formTitle.textContent = "Add Employee";
    document.getElementById("empid").value = "";
    document.getElementById("emp-email").value = "";
    document.getElementById("position").value = "";
    document.getElementById("department").value = "";
    document.getElementById("date").value = "";
  }

  formContainer.style.display = "block";
}

// Hide employee form
function hideEmployeeForm() {
  document.querySelector(".adedemp").style.display = "none";
  editingEmployeeIndex = null;
}

// Save employee
function saveEmployee() {
  const empId = document.getElementById("empid").value.trim();
  const userEmail = document.getElementById("emp-email").value.trim();
  const position = document.getElementById("position").value.trim();
  const deptId = parseInt(document.getElementById("department").value);
  const hireDate = document.getElementById("date").value;

  // Validation
  if (!empId || !userEmail || !position || !deptId) {
    alert("Please fill in all required fields");
    return;
  }

  // Verify user email exists
  const user = window.db.accounts.find((a) => a.email === userEmail);
  if (!user) {
    alert("User email not found in accounts");
    return;
  }

  if (editingEmployeeIndex !== null) {
    // Update existing employee
    const emp = window.db.employees[editingEmployeeIndex];
    emp.id = empId;
    emp.userId = userEmail;
    emp.position = position;
    emp.deptId = deptId;
    emp.hireDate = hireDate;
  } else {
    // Add new employee
    window.db.employees.push({
      id: empId,
      userId: userEmail,
      position: position,
      deptId: deptId,
      hireDate: hireDate,
    });
  }

  saveToStorage();
  renderEmployeesTable();
  hideEmployeeForm();
  alert("Employee saved successfully!");
}

// Edit employee
function editEmployee(index) {
  showEmployeeForm(index);
}

// Delete employee
function deleteEmployee(index) {
  if (confirm("Delete this employee?")) {
    window.db.employees.splice(index, 1);
    saveToStorage();
    renderEmployeesTable();
  }
}

// ============================================
// REQUESTS MANAGEMENT
// ============================================

// Render the requests table - only show current user's requests
function renderRequestsTable() {
  if (!currentUser) return;

  const tbody = document.querySelector("#requests-table tbody");
  const table = document.getElementById("requests-table");
  const noMsg = document.getElementById("no-requests-msg");

  if (!tbody) return;

  // Filter requests for current user
  const userRequests = window.db.requests.filter(
    (req) => req.employeeEmail === currentUser.email,
  );

  if (userRequests.length === 0) {
    table.style.display = "none";
    noMsg.style.display = "block";
    return;
  }

  table.style.display = "table";
  noMsg.style.display = "none";

  tbody.innerHTML = "";

  userRequests.forEach((req) => {
    // Status badge styling
    let badgeClass = "bg-warning"; // Pending
    if (req.status === "Approved") badgeClass = "bg-success";
    if (req.status === "Rejected") badgeClass = "bg-danger";

    // Format items for display
    const itemsDisplay = req.items
      .map((item) => `${item.name} (${item.qty})`)
      .join(", ");

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${req.type}</td>
      <td>${itemsDisplay}</td>
      <td>${req.date}</td>
      <td><span class="badge ${badgeClass}">${req.status}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// Initialize the items container with one empty item
function initRequestModal() {
  const container = document.getElementById("items-container");
  container.innerHTML = "";
  addRequestItem();
}

// Add a new item row to the modal
function addRequestItem() {
  const container = document.getElementById("items-container");

  const div = document.createElement("div");
  div.className = "input-group mb-2";
  div.innerHTML = `
    <input type="text" class="form-control item-name" placeholder="Item name">
    <input type="number" class="form-control item-qty" value="1" min="1" style="max-width: 70px;">
    <button class="btn btn-outline-danger" type="button" onclick="removeRequestItem(this)">×</button>
  `;
  container.appendChild(div);
}

// Remove an item row from the modal
function removeRequestItem(btn) {
  const container = document.getElementById("items-container");
  const items = container.querySelectorAll(".input-group");

  // Don't remove if it's the last item
  if (items.length <= 1) {
    alert("At least one item is required");
    return;
  }

  btn.closest(".input-group").remove();
}

// Submit the new request
function submitRequest() {
  const type = document.getElementById("request-type").value;
  const itemRows = document.querySelectorAll("#items-container .input-group");

  // Collect items
  const items = [];
  itemRows.forEach((row) => {
    const name = row.querySelector(".item-name").value.trim();
    const qty = parseInt(row.querySelector(".item-qty").value) || 1;

    if (name) {
      items.push({ name, qty });
    }
  });

  // Validate at least one item
  if (items.length === 0) {
    alert("Please add at least one item");
    return;
  }

  // Create request object
  const request = {
    type: type,
    items: items,
    status: "Pending",
    date: new Date().toISOString().split("T")[0], // YYYY-MM-DD format
    employeeEmail: currentUser.email,
  };

  // Save to database
  window.db.requests.push(request);
  saveToStorage();

  // Close modal
  const modal = bootstrap.Modal.getInstance(
    document.getElementById("requestModal"),
  );
  modal.hide();

  // Refresh table
  renderRequestsTable();

  alert("Request submitted successfully!");
}