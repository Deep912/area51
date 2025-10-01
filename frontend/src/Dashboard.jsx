// frontend/src/Dashboard.jsx - Complete Enhanced Version
import { useState, useEffect, useRef } from "react";
import axios from "axios";

const API_URL = "http://192.168.0.131:8000";

const Dashboard = ({ token, onLogout }) => {
  const [devices, setDevices] = useState([]);
  const [filteredDevices, setFilteredDevices] = useState([]);
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [showDeviceDetails, setShowDeviceDetails] = useState(false);
  const [showUserProfile, setShowUserProfile] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [editingDevice, setEditingDevice] = useState(false);
  const [dashboardData, setDashboardData] = useState({});
  const [userProfile, setUserProfile] = useState({});
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterEnvironment, setFilterEnvironment] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [newDevice, setNewDevice] = useState({
    name: "",
    device_type: "server",
    operating_system: "ubuntu",
    os_version: "",
    ip_address: "",
    hostname: "",
    business_criticality: "medium",
    environment: "production",
    description: "",
    location: "",
    owner_contact: "",
  });
  const [profileUpdate, setProfileUpdate] = useState({
    full_name: "",
    email: "",
    phone: "",
    company: "",
  });
  const [passwordChange, setPasswordChange] = useState({
    current_password: "",
    new_password: "",
  });

  // WebSocket for real-time updates
  const wsRef = useRef(null);
  const [realTimeStats, setRealTimeStats] = useState({});

  // Device type options with icons
  const deviceTypes = [
    { value: "server", label: "🖥️ Physical Server", icon: "🖥️" },
    { value: "virtual-server", label: "☁️ Virtual Server", icon: "☁️" },
    { value: "workstation", label: "💻 Workstation", icon: "💻" },
    { value: "laptop", label: "💻 Laptop", icon: "💻" },
    { value: "desktop", label: "🖥️ Desktop PC", icon: "🖥️" },
    { value: "mobile-phone", label: "📱 Mobile Phone", icon: "📱" },
    { value: "tablet", label: "📱 Tablet", icon: "📱" },
    { value: "iot-device", label: "📡 IoT Device", icon: "📡" },
    { value: "network-switch", label: "🔀 Network Switch", icon: "🔀" },
    { value: "router", label: "📡 Router", icon: "📡" },
    { value: "firewall", label: "🔥 Firewall", icon: "🔥" },
    { value: "load-balancer", label: "⚖️ Load Balancer", icon: "⚖️" },
    { value: "storage", label: "💾 Storage Device", icon: "💾" },
    { value: "printer", label: "🖨️ Printer", icon: "🖨️" },
    { value: "camera", label: "📷 Security Camera", icon: "📷" },
    { value: "embedded", label: "🔧 Embedded System", icon: "🔧" },
  ];

  // Operating system options
  const operatingSystems = [
    { value: "ubuntu", label: "🐧 Ubuntu Linux", category: "Linux" },
    { value: "debian", label: "🐧 Debian", category: "Linux" },
    { value: "centos", label: "🐧 CentOS", category: "Linux" },
    { value: "rhel", label: "🐧 Red Hat Enterprise Linux", category: "Linux" },
    { value: "fedora", label: "🐧 Fedora", category: "Linux" },
    { value: "suse", label: "🐧 SUSE Linux", category: "Linux" },
    { value: "arch", label: "🐧 Arch Linux", category: "Linux" },
    { value: "kali", label: "🐧 Kali Linux", category: "Linux" },
    { value: "alpine", label: "🐧 Alpine Linux", category: "Linux" },
    { value: "windows-11", label: "🪟 Windows 11", category: "Windows" },
    { value: "windows-10", label: "🪟 Windows 10", category: "Windows" },
    {
      value: "windows-server-2022",
      label: "🪟 Windows Server 2022",
      category: "Windows",
    },
    {
      value: "windows-server-2019",
      label: "🪟 Windows Server 2019",
      category: "Windows",
    },
    {
      value: "windows-server-2016",
      label: "🪟 Windows Server 2016",
      category: "Windows",
    },
    { value: "macos-sonoma", label: "🍎 macOS Sonoma", category: "macOS" },
    { value: "macos-ventura", label: "🍎 macOS Ventura", category: "macOS" },
    { value: "macos-monterey", label: "🍎 macOS Monterey", category: "macOS" },
    { value: "macos-bigsur", label: "🍎 macOS Big Sur", category: "macOS" },
    { value: "android", label: "🤖 Android", category: "Mobile" },
    { value: "ios", label: "📱 iOS", category: "Mobile" },
    { value: "ipados", label: "📱 iPadOS", category: "Mobile" },
    { value: "cisco-ios", label: "🔀 Cisco IOS", category: "Network" },
    { value: "juniper-junos", label: "🔀 Juniper JunOS", category: "Network" },
    { value: "pfsense", label: "🔥 pfSense", category: "Network" },
    { value: "openwrt", label: "📡 OpenWrt", category: "Network" },
    { value: "freebsd", label: "👹 FreeBSD", category: "Unix" },
    { value: "openbsd", label: "🐡 OpenBSD", category: "Unix" },
    { value: "esxi", label: "☁️ VMware ESXi", category: "Virtualization" },
    { value: "proxmox", label: "☁️ Proxmox", category: "Virtualization" },
    { value: "other", label: "❓ Other", category: "Other" },
  ];

  // Group operating systems by category
  const groupedOS = operatingSystems.reduce((acc, os) => {
    if (!acc[os.category]) {
      acc[os.category] = [];
    }
    acc[os.category].push(os);
    return acc;
  }, {});

  // Initialize WebSocket connection
  useEffect(() => {
    const connectWebSocket = () => {
      wsRef.current = new WebSocket(`ws://192.168.0.131:8000/ws`);

      wsRef.current.onopen = () => {
        console.log("🔌 WebSocket connected");
      };

      // In your existing WebSocket onmessage handler, update this part:
      wsRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log("📡 Real-time update:", data);

        if (data.type === "device_health_update") {
          setRealTimeStats(data.data);
        } else if (data.type === "manual_ping_result") {
          // Handle manual ping results from any user
          console.log("🏓 Manual ping result:", data.data);
          loadDashboard(); // Refresh devices after manual ping

          // Show notification if it was pinged by another user
          if (data.data.user !== userProfile.username) {
            showMessage(
              `🏓 ${data.data.user} pinged ${
                data.data.device_name
              }: ${data.data.status.toUpperCase()}`
            );
          }
        } else if (data.type === "device_added") {
          loadDashboard();
        } else if (data.type === "device_updated") {
          loadDashboard();
        } else if (data.type === "device_deleted") {
          loadDashboard();
        }
      };

      wsRef.current.onclose = () => {
        console.log("🔌 WebSocket disconnected, reconnecting...");
        setTimeout(connectWebSocket, 3000); // Reconnect after 3 seconds
      };

      wsRef.current.onerror = (error) => {
        console.error("❌ WebSocket error:", error);
      };
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  useEffect(() => {
    loadDashboard();
    loadUserProfile();
  }, []);

  // Filter devices based on search and filters
  useEffect(() => {
    let filtered = devices;

    if (searchQuery) {
      filtered = filtered.filter(
        (device) =>
          device.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          (device.hostname &&
            device.hostname
              .toLowerCase()
              .includes(searchQuery.toLowerCase())) ||
          (device.ip_address && device.ip_address.includes(searchQuery)) ||
          device.operating_system
            .toLowerCase()
            .includes(searchQuery.toLowerCase())
      );
    }

    if (filterType) {
      filtered = filtered.filter((device) => device.device_type === filterType);
    }

    if (filterEnvironment) {
      filtered = filtered.filter(
        (device) => device.environment === filterEnvironment
      );
    }

    if (filterStatus) {
      filtered = filtered.filter((device) => device.status === filterStatus);
    }

    setFilteredDevices(filtered);
  }, [devices, searchQuery, filterType, filterEnvironment, filterStatus]);

  const loadDashboard = async () => {
    try {
      const [dashboardRes, devicesRes] = await Promise.all([
        axios.get(`${API_URL}/api/dashboard?token=${token}`),
        axios.get(`${API_URL}/api/devices?token=${token}`),
      ]);

      setDashboardData(dashboardRes.data);
      setDevices(devicesRes.data.devices);
    } catch (error) {
      console.error("Dashboard load failed:", error);
    }
  };

  const loadUserProfile = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/profile?token=${token}`);
      setUserProfile(response.data);
      setProfileUpdate({
        full_name: response.data.full_name || "",
        email: response.data.email || "",
        phone: response.data.phone || "",
        company: response.data.company || "",
      });
    } catch (error) {
      console.error("Profile load failed:", error);
    }
  };

  const addDevice = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post(`${API_URL}/api/devices?token=${token}`, newDevice);

      setNewDevice({
        name: "",
        device_type: "server",
        operating_system: "ubuntu",
        os_version: "",
        ip_address: "",
        hostname: "",
        business_criticality: "medium",
        environment: "production",
        description: "",
        location: "",
        owner_contact: "",
      });
      setShowAddDevice(false);
      await loadDashboard();
      showMessage("✅ Device added successfully!");
    } catch (error) {
      showMessage("❌ Failed to add device");
    }
    setLoading(false);
  };

  const updateDevice = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.put(
        `${API_URL}/api/devices/${selectedDevice.id}?token=${token}`,
        selectedDevice
      );
      setEditingDevice(false);
      await loadDashboard();
      showMessage("✅ Device updated successfully!");
    } catch (error) {
      showMessage("❌ Failed to update device");
    }
    setLoading(false);
  };

  const deleteDevice = async (deviceId, deviceName) => {
    if (!confirm(`Delete "${deviceName}"?`)) return;

    try {
      await axios.delete(`${API_URL}/api/devices/${deviceId}?token=${token}`);
      await loadDashboard();
      setShowDeviceDetails(false);
      showMessage("✅ Device deleted successfully!");
    } catch (error) {
      showMessage("❌ Failed to delete device");
    }
  };

  const updateProfile = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.put(`${API_URL}/api/profile?token=${token}`, profileUpdate);
      await loadUserProfile();
      showMessage("✅ Profile updated successfully!");
    } catch (error) {
      showMessage("❌ Failed to update profile");
    }
    setLoading(false);
  };

  const changePassword = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post(
        `${API_URL}/api/change-password?token=${token}`,
        passwordChange
      );
      setPasswordChange({ current_password: "", new_password: "" });
      showMessage("✅ Password changed successfully!");
    } catch (error) {
      showMessage("❌ Failed to change password");
    }
    setLoading(false);
  };

  const showMessage = (msg) => {
    setMessage(msg);
    setTimeout(() => setMessage(""), 3000);
  };

  const getDeviceIcon = (deviceType) => {
    const device = deviceTypes.find((d) => d.value === deviceType);
    return device ? device.icon : "🖥️";
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "online":
        return "#10b981";
      case "offline":
        return "#ef4444";
      default:
        return "#f59e0b";
    }
  };

  const formatUptime = (seconds) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const clearFilters = () => {
    setSearchQuery("");
    setFilterType("");
    setFilterEnvironment("");
    setFilterStatus("");
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100vw",
        background: "#f8fafc",
        display: "flex",
        fontFamily: '"Inter", "Segoe UI", system-ui, sans-serif',
      }}
    >
      {/* Sidebar */}
      <div
        style={{
          width: "280px",
          background: "#ffffff",
          borderRight: "1px solid #e2e8f0",
          padding: "32px 0",
          flexShrink: 0,
        }}
      >
        {/* Logo */}
        <div style={{ padding: "0 32px", marginBottom: "48px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                width: "32px",
                height: "32px",
                background: "linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)",
                borderRadius: "8px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "18px",
                color: "white",
              }}
            >
              🛡️
            </div>
            <span
              style={{ fontSize: "20px", fontWeight: "700", color: "#1e293b" }}
            >
              Area51
            </span>
          </div>
        </div>

        {/* Navigation */}
        <div style={{ padding: "0 16px" }}>
          {[
            { id: "overview", icon: "📊", label: "Dashboard" },
            { id: "devices", icon: "💻", label: "Devices" },
            { id: "security", icon: "🔒", label: "Security" },
          ].map((item) => (
            <div
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "12px",
                padding: "12px 16px",
                margin: "4px 0",
                borderRadius: "8px",
                background: activeTab === item.id ? "#f0f4ff" : "transparent",
                color: activeTab === item.id ? "#6366f1" : "#64748b",
                cursor: "pointer",
                transition: "all 0.2s ease",
                fontSize: "15px",
                fontWeight: activeTab === item.id ? "600" : "500",
              }}
            >
              <span style={{ fontSize: "16px" }}>{item.icon}</span>
              {item.label}
            </div>
          ))}
        </div>

        {/* User Profile */}
        <div
          style={{
            position: "absolute",
            bottom: "32px",
            left: "16px",
            right: "16px",
            padding: "16px",
            background: "#f8fafc",
            borderRadius: "12px",
            display: "flex",
            alignItems: "center",
            gap: "12px",
          }}
        >
          <div
            style={{
              width: "40px",
              height: "40px",
              background: "#e2e8f0",
              borderRadius: "50%",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "16px",
            }}
          >
            👤
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{ fontSize: "14px", fontWeight: "600", color: "#1e293b" }}
            >
              {dashboardData.user || "User"}
            </div>
            <div style={{ fontSize: "12px", color: "#64748b" }}>
              Administrator
            </div>
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              onClick={() => setShowUserProfile(true)}
              style={{
                background: "none",
                border: "none",
                color: "#64748b",
                cursor: "pointer",
                fontSize: "16px",
                padding: "4px",
              }}
              title="Profile Settings"
            >
              ⚙️
            </button>
            <button
              onClick={onLogout}
              style={{
                background: "none",
                border: "none",
                color: "#64748b",
                cursor: "pointer",
                fontSize: "16px",
                padding: "4px",
              }}
              title="Logout"
            >
              🚪
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, overflow: "hidden" }}>
        {/* Header */}
        <div
          style={{
            background: "#ffffff",
            borderBottom: "1px solid #e2e8f0",
            padding: "24px 32px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div>
            <h1
              style={{
                margin: "0",
                fontSize: "28px",
                fontWeight: "700",
                color: "#1e293b",
              }}
            >
              {activeTab === "overview"
                ? "Security Dashboard"
                : activeTab === "devices"
                ? "Device Management"
                : "Security Overview"}
            </h1>
            <div
              style={{
                margin: "4px 0 0 0",
                color: "#64748b",
                fontSize: "16px",
                display: "flex",
                gap: "16px",
              }}
            >
              <span>{dashboardData.total_devices || 0} devices monitored</span>
              {realTimeStats.online_devices !== undefined && (
                <span style={{ color: "#10b981" }}>
                  {realTimeStats.online_devices} online
                </span>
              )}
              <span>Real-time security status</span>
            </div>
          </div>
          <button
            onClick={() => setShowAddDevice(true)}
            style={{
              background: "#6366f1",
              color: "white",
              border: "none",
              padding: "12px 20px",
              borderRadius: "8px",
              cursor: "pointer",
              fontSize: "14px",
              fontWeight: "600",
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            + Add Device
          </button>
        </div>

        {/* Content Area */}
        <div
          style={{
            padding: "32px",
            height: "calc(100vh - 120px)",
            overflow: "auto",
          }}
        >
          {/* Overview Tab */}
          {activeTab === "overview" && (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "24px",
                height: "100%",
              }}
            >
              {/* Security Score */}
              <div
                style={{
                  background: "#ffffff",
                  borderRadius: "16px",
                  padding: "24px",
                  border: "1px solid #e2e8f0",
                }}
              >
                <h3
                  style={{
                    margin: "0 0 16px 0",
                    fontSize: "18px",
                    fontWeight: "600",
                    color: "#1e293b",
                  }}
                >
                  Security Score
                </h3>
                <div style={{ textAlign: "center", padding: "20px 0" }}>
                  <div
                    style={{
                      fontSize: "48px",
                      fontWeight: "700",
                      color: "#6366f1",
                      margin: "0 0 8px 0",
                    }}
                  >
                    85
                  </div>
                  <div
                    style={{
                      color: "#64748b",
                      fontSize: "14px",
                      marginBottom: "16px",
                    }}
                  >
                    Good Security Level
                    {realTimeStats.timestamp && (
                      <div style={{ fontSize: "12px", marginTop: "4px" }}>
                        Last updated:{" "}
                        {new Date(realTimeStats.timestamp).toLocaleTimeString()}
                      </div>
                    )}
                  </div>

                  <div
                    style={{
                      width: "100%",
                      height: "8px",
                      background: "#f1f5f9",
                      borderRadius: "4px",
                      overflow: "hidden",
                      margin: "16px 0",
                    }}
                  >
                    <div
                      style={{
                        width: "85%",
                        height: "100%",
                        background: "#6366f1",
                        borderRadius: "4px",
                      }}
                    ></div>
                  </div>

                  <div
                    style={{
                      marginTop: "16px",
                      color: "#6366f1",
                      fontSize: "14px",
                      fontWeight: "500",
                    }}
                  >
                    Based on {devices.length} monitored devices
                  </div>
                </div>
              </div>

              {/* Device Statistics */}
              <div
                style={{
                  background: "#ffffff",
                  borderRadius: "16px",
                  padding: "24px",
                  border: "1px solid #e2e8f0",
                }}
              >
                <h3
                  style={{
                    margin: "0 0 20px 0",
                    fontSize: "18px",
                    fontWeight: "600",
                    color: "#1e293b",
                  }}
                >
                  Real-time Statistics
                </h3>

                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "16px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <div
                        style={{
                          width: "8px",
                          height: "8px",
                          background: "#10b981",
                          borderRadius: "50%",
                        }}
                      ></div>
                      <span style={{ fontSize: "14px", color: "#1e293b" }}>
                        Total Devices
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#1e293b",
                      }}
                    >
                      {realTimeStats.total_devices ||
                        dashboardData.total_devices ||
                        0}
                    </span>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <div
                        style={{
                          width: "8px",
                          height: "8px",
                          background: "#6366f1",
                          borderRadius: "50%",
                        }}
                      ></div>
                      <span style={{ fontSize: "14px", color: "#1e293b" }}>
                        Online Devices
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#10b981",
                      }}
                    >
                      {realTimeStats.online_devices ||
                        devices.filter((d) => d.status === "online").length}
                    </span>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <div
                        style={{
                          width: "8px",
                          height: "8px",
                          background: "#f59e0b",
                          borderRadius: "50%",
                        }}
                      ></div>
                      <span style={{ fontSize: "14px", color: "#1e293b" }}>
                        Production Systems
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#1e293b",
                      }}
                    >
                      {
                        devices.filter((d) => d.environment === "production")
                          .length
                      }
                    </span>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <div
                        style={{
                          width: "8px",
                          height: "8px",
                          background: "#ef4444",
                          borderRadius: "50%",
                        }}
                      ></div>
                      <span style={{ fontSize: "14px", color: "#1e293b" }}>
                        Critical Systems
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#1e293b",
                      }}
                    >
                      {
                        devices.filter(
                          (d) => d.business_criticality === "critical"
                        ).length
                      }
                    </span>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <div
                        style={{
                          width: "8px",
                          height: "8px",
                          background: "#8b5cf6",
                          borderRadius: "50%",
                        }}
                      ></div>
                      <span style={{ fontSize: "14px", color: "#1e293b" }}>
                        Offline Devices
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#ef4444",
                      }}
                    >
                      {devices.filter((d) => d.status === "offline").length}
                    </span>
                  </div>
                </div>
              </div>

              {/* Recent Activity */}
              <div
                style={{
                  background: "#ffffff",
                  borderRadius: "16px",
                  padding: "24px",
                  border: "1px solid #e2e8f0",
                  gridColumn: "span 2",
                }}
              >
                <h3
                  style={{
                    margin: "0 0 20px 0",
                    fontSize: "18px",
                    fontWeight: "600",
                    color: "#1e293b",
                  }}
                >
                  Recent Activity & Device Health
                </h3>

                {devices.length === 0 ? (
                  <div
                    style={{
                      textAlign: "center",
                      padding: "40px",
                      color: "#64748b",
                    }}
                  >
                    <div
                      style={{
                        fontSize: "32px",
                        marginBottom: "12px",
                        opacity: "0.5",
                      }}
                    >
                      📊
                    </div>
                    <p style={{ margin: "0", fontSize: "14px" }}>
                      No activity yet. Add devices to start monitoring.
                    </p>
                  </div>
                ) : (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "12px",
                    }}
                  >
                    {devices.slice(0, 5).map((device, i) => (
                      <div
                        key={device.id}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "16px",
                          padding: "16px",
                          background: "#f8fafc",
                          borderRadius: "12px",
                          border: "1px solid #e2e8f0",
                        }}
                      >
                        <div
                          style={{
                            width: "12px",
                            height: "12px",
                            background: getStatusColor(device.status),
                            borderRadius: "50%",
                          }}
                        ></div>

                        <div style={{ fontSize: "20px" }}>
                          {getDeviceIcon(device.device_type)}
                        </div>

                        <div style={{ flex: 1 }}>
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: "12px",
                            }}
                          >
                            <span
                              style={{
                                fontSize: "14px",
                                fontWeight: "600",
                                color: "#1e293b",
                              }}
                            >
                              {device.name}
                            </span>
                            <span
                              style={{
                                fontSize: "12px",
                                padding: "2px 8px",
                                borderRadius: "12px",
                                background:
                                  device.status === "online"
                                    ? "#dcfce7"
                                    : "#fef2f2",
                                color:
                                  device.status === "online"
                                    ? "#166534"
                                    : "#dc2626",
                              }}
                            >
                              {device.status}
                            </span>
                          </div>
                          <div
                            style={{
                              fontSize: "12px",
                              color: "#64748b",
                              marginTop: "2px",
                            }}
                          >
                            {device.environment} • {device.business_criticality}
                            {device.last_seen && (
                              <span>
                                {" "}
                                • Last seen:{" "}
                                {new Date(
                                  device.last_seen
                                ).toLocaleTimeString()}
                              </span>
                            )}
                          </div>
                        </div>

                        <div
                          style={{
                            display: "flex",
                            gap: "16px",
                            fontSize: "12px",
                            color: "#64748b",
                          }}
                        >
                          <div>CPU: {device.cpu_usage?.toFixed(1) || 0}%</div>
                          <div>
                            RAM: {device.memory_usage?.toFixed(1) || 0}%
                          </div>
                          <div>Uptime: {formatUptime(device.uptime || 0)}</div>
                        </div>

                        <button
                          onClick={() => {
                            setSelectedDevice(device);
                            setShowDeviceDetails(true);
                          }}
                          style={{
                            background: "#6366f1",
                            color: "white",
                            border: "none",
                            padding: "6px 12px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            cursor: "pointer",
                          }}
                        >
                          Details
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Devices Tab with Search & Filters */}
          {activeTab === "devices" && (
            <div
              style={{ display: "flex", flexDirection: "column", gap: "24px" }}
            >
              {/* Search and Filters */}
              <div
                style={{
                  background: "#ffffff",
                  borderRadius: "16px",
                  padding: "20px",
                  border: "1px solid #e2e8f0",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    gap: "16px",
                    alignItems: "center",
                    flexWrap: "wrap",
                  }}
                >
                  {/* Search */}
                  <div style={{ position: "relative", minWidth: "300px" }}>
                    <input
                      type="text"
                      placeholder="Search devices..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      style={{
                        width: "100%",
                        padding: "10px 16px 10px 40px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "8px",
                        fontSize: "14px",
                        boxSizing: "border-box",
                      }}
                    />
                    <span
                      style={{
                        position: "absolute",
                        left: "12px",
                        top: "50%",
                        transform: "translateY(-50%)",
                        fontSize: "16px",
                        color: "#64748b",
                      }}
                    >
                      🔍
                    </span>
                  </div>

                  {/* Device Type Filter */}
                  <select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    style={{
                      padding: "10px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      minWidth: "150px",
                    }}
                  >
                    <option value="">All Types</option>
                    {deviceTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>

                  {/* Environment Filter */}
                  <select
                    value={filterEnvironment}
                    onChange={(e) => setFilterEnvironment(e.target.value)}
                    style={{
                      padding: "10px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      minWidth: "150px",
                    }}
                  >
                    <option value="">All Environments</option>
                    <option value="development">🟦 Development</option>
                    <option value="testing">🟨 Testing</option>
                    <option value="staging">🟧 Staging</option>
                    <option value="production">🟥 Production</option>
                  </select>

                  {/* Status Filter */}
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    style={{
                      padding: "10px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      minWidth: "120px",
                    }}
                  >
                    <option value="">All Status</option>
                    <option value="online">🟢 Online</option>
                    <option value="offline">🔴 Offline</option>
                    <option value="unknown">🟡 Unknown</option>
                  </select>

                  {/* Clear Filters */}
                  {(searchQuery ||
                    filterType ||
                    filterEnvironment ||
                    filterStatus) && (
                    <button
                      onClick={clearFilters}
                      style={{
                        background: "#f3f4f6",
                        color: "#374151",
                        border: "1px solid #d1d5db",
                        padding: "10px 16px",
                        borderRadius: "8px",
                        fontSize: "14px",
                        cursor: "pointer",
                      }}
                    >
                      Clear Filters
                    </button>
                  )}

                  {/* Results Count */}
                  <div
                    style={{
                      marginLeft: "auto",
                      fontSize: "14px",
                      color: "#64748b",
                    }}
                  >
                    Showing {filteredDevices.length} of {devices.length} devices
                  </div>
                </div>
              </div>

              {/* Device List */}
              <div
                style={{
                  background: "#ffffff",
                  borderRadius: "16px",
                  padding: "24px",
                  border: "1px solid #e2e8f0",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "24px",
                  }}
                >
                  <h2
                    style={{
                      margin: "0",
                      fontSize: "20px",
                      fontWeight: "600",
                      color: "#1e293b",
                    }}
                  >
                    Device Inventory
                  </h2>
                </div>

                {filteredDevices.length === 0 ? (
                  <div
                    style={{
                      textAlign: "center",
                      padding: "60px 20px",
                      color: "#64748b",
                    }}
                  >
                    <div
                      style={{
                        fontSize: "48px",
                        marginBottom: "16px",
                        opacity: "0.5",
                      }}
                    >
                      {devices.length === 0 ? "🖥️" : "🔍"}
                    </div>
                    <h3
                      style={{
                        margin: "0 0 8px 0",
                        fontSize: "18px",
                        fontWeight: "600",
                        color: "#374151",
                      }}
                    >
                      {devices.length === 0
                        ? "No devices registered"
                        : "No devices found"}
                    </h3>
                    <p style={{ margin: "0", fontSize: "14px" }}>
                      {devices.length === 0
                        ? "Add your first device to start monitoring your infrastructure"
                        : "Try adjusting your search or filter criteria"}
                    </p>
                  </div>
                ) : (
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(auto-fit, minmax(380px, 1fr))",
                      gap: "16px",
                    }}
                  >
                    {filteredDevices.map((device) => (
                      <div
                        key={device.id}
                        style={{
                          background: "#f8fafc",
                          borderRadius: "12px",
                          padding: "20px",
                          border: "1px solid #e2e8f0",
                          transition: "all 0.2s ease",
                          cursor: "pointer",
                        }}
                        onClick={() => {
                          setSelectedDevice(device);
                          setShowDeviceDetails(true);
                        }}
                        onMouseOver={(e) => {
                          e.currentTarget.style.boxShadow =
                            "0 4px 12px rgba(0, 0, 0, 0.1)";
                          e.currentTarget.style.transform = "translateY(-2px)";
                        }}
                        onMouseOut={(e) => {
                          e.currentTarget.style.boxShadow = "none";
                          e.currentTarget.style.transform = "translateY(0)";
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "16px",
                          }}
                        >
                          <div
                            style={{
                              width: "48px",
                              height: "48px",
                              background: "#dbeafe",
                              borderRadius: "12px",
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              fontSize: "20px",
                            }}
                          >
                            {getDeviceIcon(device.device_type)}
                          </div>

                          <div style={{ flex: 1 }}>
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "8px",
                                marginBottom: "6px",
                              }}
                            >
                              <h4
                                style={{
                                  margin: "0",
                                  fontSize: "16px",
                                  fontWeight: "600",
                                  color: "#1e293b",
                                }}
                              >
                                {device.name}
                              </h4>
                              <div
                                style={{
                                  width: "8px",
                                  height: "8px",
                                  background: getStatusColor(device.status),
                                  borderRadius: "50%",
                                }}
                              ></div>
                            </div>

                            <p
                              style={{
                                margin: "0 0 12px 0",
                                fontSize: "14px",
                                color: "#64748b",
                              }}
                            >
                              {device.operating_system} {device.os_version}
                            </p>

                            <div
                              style={{
                                display: "flex",
                                gap: "8px",
                                flexWrap: "wrap",
                                marginBottom: "12px",
                              }}
                            >
                              <span
                                style={{
                                  padding: "4px 12px",
                                  background:
                                    device.environment === "production"
                                      ? "#fecaca"
                                      : device.environment === "staging"
                                      ? "#fef3c7"
                                      : "#d1fae5",
                                  color:
                                    device.environment === "production"
                                      ? "#dc2626"
                                      : device.environment === "staging"
                                      ? "#d97706"
                                      : "#059669",
                                  borderRadius: "12px",
                                  fontSize: "12px",
                                  fontWeight: "500",
                                }}
                              >
                                {device.environment.toUpperCase()}
                              </span>
                              <span
                                style={{
                                  padding: "4px 12px",
                                  background: "#f3f4f6",
                                  color: "#374151",
                                  borderRadius: "12px",
                                  fontSize: "12px",
                                }}
                              >
                                {device.ip_address || "No IP"}
                              </span>
                            </div>

                            {/* Health Metrics */}
                            <div
                              style={{
                                display: "flex",
                                gap: "12px",
                                fontSize: "12px",
                                color: "#64748b",
                              }}
                            >
                              <span>
                                CPU: {device.cpu_usage?.toFixed(1) || 0}%
                              </span>
                              <span>
                                RAM: {device.memory_usage?.toFixed(1) || 0}%
                              </span>
                              <span>
                                Up: {formatUptime(device.uptime || 0)}
                              </span>
                            </div>
                          </div>

                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              deleteDevice(device.id, device.name);
                            }}
                            style={{
                              background: "none",
                              border: "none",
                              color: "#ef4444",
                              cursor: "pointer",
                              fontSize: "16px",
                              padding: "4px",
                              borderRadius: "4px",
                            }}
                            onMouseOver={(e) =>
                              (e.target.style.background = "#fef2f2")
                            }
                            onMouseOut={(e) =>
                              (e.target.style.background = "none")
                            }
                          >
                            🗑️
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === "security" && (
            <div
              style={{
                background: "#ffffff",
                borderRadius: "16px",
                padding: "60px",
                border: "1px solid #e2e8f0",
                textAlign: "center",
              }}
            >
              <div
                style={{
                  fontSize: "64px",
                  marginBottom: "24px",
                  opacity: "0.3",
                }}
              >
                🔒
              </div>
              <h2
                style={{
                  margin: "0 0 12px 0",
                  fontSize: "24px",
                  fontWeight: "600",
                  color: "#1e293b",
                }}
              >
                Security Center
              </h2>
              <p style={{ margin: "0", color: "#64748b", fontSize: "16px" }}>
                Advanced security features coming soon. Monitor device
                vulnerabilities and security alerts.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Device Details Modal */}
      {showDeviceDetails && selectedDevice && (
        <div
          style={{
            position: "fixed",
            top: "0",
            left: "0",
            right: "0",
            bottom: "0",
            background: "rgba(0, 0, 0, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: "#ffffff",
              borderRadius: "16px",
              padding: "32px",
              width: "90%",
              maxWidth: "700px",
              maxHeight: "90vh",
              overflowY: "auto",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: "24px",
              }}
            >
              <div>
                <h2
                  style={{
                    margin: "0 0 8px 0",
                    fontSize: "24px",
                    fontWeight: "600",
                    color: "#1e293b",
                  }}
                >
                  {selectedDevice.name}
                </h2>
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <div
                    style={{
                      width: "8px",
                      height: "8px",
                      background: getStatusColor(selectedDevice.status),
                      borderRadius: "50%",
                    }}
                  ></div>
                  <span
                    style={{
                      fontSize: "14px",
                      color: "#64748b",
                      textTransform: "capitalize",
                    }}
                  >
                    {selectedDevice.status}
                  </span>
                  {selectedDevice.last_seen && (
                    <span style={{ fontSize: "14px", color: "#64748b" }}>
                      • Last seen:{" "}
                      {new Date(selectedDevice.last_seen).toLocaleString()}
                    </span>
                  )}
                </div>
              </div>

              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  onClick={() => setEditingDevice(true)}
                  style={{
                    background: "#6366f1",
                    color: "white",
                    border: "none",
                    padding: "8px 16px",
                    borderRadius: "6px",
                    fontSize: "14px",
                    cursor: "pointer",
                  }}
                >
                  Edit
                </button>
                <button
                  onClick={() => setShowDeviceDetails(false)}
                  style={{
                    background: "none",
                    border: "1px solid #e2e8f0",
                    color: "#64748b",
                    padding: "8px 16px",
                    borderRadius: "6px",
                    fontSize: "14px",
                    cursor: "pointer",
                  }}
                >
                  Close
                </button>
              </div>
            </div>

            {editingDevice ? (
              // Edit Form
              <form
                onSubmit={updateDevice}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "20px",
                }}
              >
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "16px",
                  }}
                >
                  <div>
                    <label
                      style={{
                        display: "block",
                        marginBottom: "4px",
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#374151",
                      }}
                    >
                      Device Name
                    </label>
                    <input
                      type="text"
                      value={selectedDevice.name}
                      onChange={(e) =>
                        setSelectedDevice({
                          ...selectedDevice,
                          name: e.target.value,
                        })
                      }
                      style={{
                        width: "100%",
                        padding: "10px 12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "6px",
                        fontSize: "14px",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>

                  <div>
                    <label
                      style={{
                        display: "block",
                        marginBottom: "4px",
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#374151",
                      }}
                    >
                      IP Address
                    </label>
                    <input
                      type="text"
                      value={selectedDevice.ip_address || ""}
                      onChange={(e) =>
                        setSelectedDevice({
                          ...selectedDevice,
                          ip_address: e.target.value,
                        })
                      }
                      style={{
                        width: "100%",
                        padding: "10px 12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "6px",
                        fontSize: "14px",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>
                </div>

                <div>
                  <label
                    style={{
                      display: "block",
                      marginBottom: "4px",
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#374151",
                    }}
                  >
                    Description
                  </label>
                  <textarea
                    value={selectedDevice.description || ""}
                    onChange={(e) =>
                      setSelectedDevice({
                        ...selectedDevice,
                        description: e.target.value,
                      })
                    }
                    rows="3"
                    style={{
                      width: "100%",
                      padding: "10px 12px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "6px",
                      fontSize: "14px",
                      boxSizing: "border-box",
                      resize: "vertical",
                    }}
                    placeholder="Device description..."
                  />
                </div>

                <div
                  style={{ display: "flex", gap: "12px", marginTop: "16px" }}
                >
                  <button
                    type="button"
                    onClick={() => setEditingDevice(false)}
                    style={{
                      flex: 1,
                      padding: "12px",
                      background: "#f8fafc",
                      color: "#64748b",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      cursor: "pointer",
                      fontSize: "14px",
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    style={{
                      flex: 1,
                      padding: "12px",
                      background: loading ? "#94a3b8" : "#6366f1",
                      color: "white",
                      border: "none",
                      borderRadius: "8px",
                      cursor: loading ? "not-allowed" : "pointer",
                      fontSize: "14px",
                      fontWeight: "500",
                    }}
                  >
                    {loading ? "Updating..." : "Update Device"}
                  </button>
                </div>
              </form>
            ) : (
              // Device Details View
              <div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "24px",
                    marginBottom: "32px",
                  }}
                >
                  {/* Basic Info */}
                  <div>
                    <h3
                      style={{
                        margin: "0 0 16px 0",
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#1e293b",
                      }}
                    >
                      Basic Information
                    </h3>
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "12px",
                      }}
                    >
                      <div>
                        <span
                          style={{
                            fontSize: "12px",
                            color: "#64748b",
                            textTransform: "uppercase",
                          }}
                        >
                          Device Type
                        </span>
                        <div
                          style={{
                            fontSize: "14px",
                            fontWeight: "500",
                            color: "#1e293b",
                          }}
                        >
                          {getDeviceIcon(selectedDevice.device_type)}{" "}
                          {deviceTypes.find(
                            (t) => t.value === selectedDevice.device_type
                          )?.label || selectedDevice.device_type}
                        </div>
                      </div>

                      <div>
                        <span
                          style={{
                            fontSize: "12px",
                            color: "#64748b",
                            textTransform: "uppercase",
                          }}
                        >
                          Operating System
                        </span>
                        <div
                          style={{
                            fontSize: "14px",
                            fontWeight: "500",
                            color: "#1e293b",
                          }}
                        >
                          {selectedDevice.operating_system}{" "}
                          {selectedDevice.os_version}
                        </div>
                      </div>

                      <div>
                        <span
                          style={{
                            fontSize: "12px",
                            color: "#64748b",
                            textTransform: "uppercase",
                          }}
                        >
                          Network
                        </span>
                        <div
                          style={{
                            fontSize: "14px",
                            fontWeight: "500",
                            color: "#1e293b",
                          }}
                        >
                          {selectedDevice.ip_address || "No IP Address"}
                          {selectedDevice.hostname && (
                            <div style={{ fontSize: "12px", color: "#64748b" }}>
                              Hostname: {selectedDevice.hostname}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Health Metrics */}
                  <div>
                    <h3
                      style={{
                        margin: "0 0 16px 0",
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#1e293b",
                      }}
                    >
                      Health Metrics
                    </h3>
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "16px",
                      }}
                    >
                      {/* CPU Usage */}
                      <div>
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "4px",
                          }}
                        >
                          <span style={{ fontSize: "12px", color: "#64748b" }}>
                            CPU USAGE
                          </span>
                          <span
                            style={{
                              fontSize: "12px",
                              fontWeight: "500",
                              color: "#1e293b",
                            }}
                          >
                            {selectedDevice.cpu_usage?.toFixed(1) || 0}%
                          </span>
                        </div>
                        <div
                          style={{
                            width: "100%",
                            height: "6px",
                            background: "#f1f5f9",
                            borderRadius: "3px",
                          }}
                        >
                          <div
                            style={{
                              width: `${selectedDevice.cpu_usage || 0}%`,
                              height: "100%",
                              background:
                                selectedDevice.cpu_usage > 80
                                  ? "#ef4444"
                                  : selectedDevice.cpu_usage > 60
                                  ? "#f59e0b"
                                  : "#10b981",
                              borderRadius: "3px",
                            }}
                          ></div>
                        </div>
                      </div>

                      {/* Memory Usage */}
                      <div>
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "4px",
                          }}
                        >
                          <span style={{ fontSize: "12px", color: "#64748b" }}>
                            MEMORY USAGE
                          </span>
                          <span
                            style={{
                              fontSize: "12px",
                              fontWeight: "500",
                              color: "#1e293b",
                            }}
                          >
                            {selectedDevice.memory_usage?.toFixed(1) || 0}%
                          </span>
                        </div>
                        <div
                          style={{
                            width: "100%",
                            height: "6px",
                            background: "#f1f5f9",
                            borderRadius: "3px",
                          }}
                        >
                          <div
                            style={{
                              width: `${selectedDevice.memory_usage || 0}%`,
                              height: "100%",
                              background:
                                selectedDevice.memory_usage > 80
                                  ? "#ef4444"
                                  : selectedDevice.memory_usage > 60
                                  ? "#f59e0b"
                                  : "#10b981",
                              borderRadius: "3px",
                            }}
                          ></div>
                        </div>
                      </div>

                      {/* Disk Usage */}
                      <div>
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "4px",
                          }}
                        >
                          <span style={{ fontSize: "12px", color: "#64748b" }}>
                            DISK USAGE
                          </span>
                          <span
                            style={{
                              fontSize: "12px",
                              fontWeight: "500",
                              color: "#1e293b",
                            }}
                          >
                            {selectedDevice.disk_usage?.toFixed(1) || 0}%
                          </span>
                        </div>
                        <div
                          style={{
                            width: "100%",
                            height: "6px",
                            background: "#f1f5f9",
                            borderRadius: "3px",
                          }}
                        >
                          <div
                            style={{
                              width: `${selectedDevice.disk_usage || 0}%`,
                              height: "100%",
                              background:
                                selectedDevice.disk_usage > 80
                                  ? "#ef4444"
                                  : selectedDevice.disk_usage > 60
                                  ? "#f59e0b"
                                  : "#10b981",
                              borderRadius: "3px",
                            }}
                          ></div>
                        </div>
                      </div>

                      {/* Uptime */}
                      <div>
                        <span style={{ fontSize: "12px", color: "#64748b" }}>
                          UPTIME
                        </span>
                        <div
                          style={{
                            fontSize: "14px",
                            fontWeight: "500",
                            color: "#1e293b",
                          }}
                        >
                          {formatUptime(selectedDevice.uptime || 0)}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Configuration */}
                <div>
                  <h3
                    style={{
                      margin: "0 0 16px 0",
                      fontSize: "16px",
                      fontWeight: "600",
                      color: "#1e293b",
                    }}
                  >
                    Configuration
                  </h3>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr 1fr",
                      gap: "16px",
                    }}
                  >
                    <div>
                      <span
                        style={{
                          fontSize: "12px",
                          color: "#64748b",
                          textTransform: "uppercase",
                        }}
                      >
                        Environment
                      </span>
                      <div
                        style={{
                          padding: "4px 12px",
                          borderRadius: "12px",
                          fontSize: "12px",
                          fontWeight: "500",
                          background:
                            selectedDevice.environment === "production"
                              ? "#fecaca"
                              : selectedDevice.environment === "staging"
                              ? "#fef3c7"
                              : "#d1fae5",
                          color:
                            selectedDevice.environment === "production"
                              ? "#dc2626"
                              : selectedDevice.environment === "staging"
                              ? "#d97706"
                              : "#059669",
                          textAlign: "center",
                          textTransform: "uppercase",
                        }}
                      >
                        {selectedDevice.environment}
                      </div>
                    </div>

                    <div>
                      <span
                        style={{
                          fontSize: "12px",
                          color: "#64748b",
                          textTransform: "uppercase",
                        }}
                      >
                        Priority
                      </span>
                      <div
                        style={{
                          padding: "4px 12px",
                          borderRadius: "12px",
                          fontSize: "12px",
                          fontWeight: "500",
                          background:
                            selectedDevice.business_criticality === "critical"
                              ? "#fecaca"
                              : selectedDevice.business_criticality === "high"
                              ? "#fef3c7"
                              : "#f3f4f6",
                          color:
                            selectedDevice.business_criticality === "critical"
                              ? "#dc2626"
                              : selectedDevice.business_criticality === "high"
                              ? "#d97706"
                              : "#374151",
                          textAlign: "center",
                          textTransform: "uppercase",
                        }}
                      >
                        {selectedDevice.business_criticality}
                      </div>
                    </div>

                    <div>
                      <span
                        style={{
                          fontSize: "12px",
                          color: "#64748b",
                          textTransform: "uppercase",
                        }}
                      >
                        Added
                      </span>
                      <div
                        style={{
                          fontSize: "12px",
                          fontWeight: "500",
                          color: "#1e293b",
                        }}
                      >
                        {new Date(
                          selectedDevice.created_at
                        ).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Description */}
                {selectedDevice.description && (
                  <div style={{ marginTop: "24px" }}>
                    <h3
                      style={{
                        margin: "0 0 12px 0",
                        fontSize: "16px",
                        fontWeight: "600",
                        color: "#1e293b",
                      }}
                    >
                      Description
                    </h3>
                    <p
                      style={{
                        margin: "0",
                        fontSize: "14px",
                        color: "#64748b",
                        lineHeight: "1.5",
                      }}
                    >
                      {selectedDevice.description}
                    </p>
                  </div>
                )}

                {/* Action Buttons */}
                <div
                  style={{
                    marginTop: "32px",
                    paddingTop: "24px",
                    borderTop: "1px solid #e2e8f0",
                    display: "flex",
                    gap: "12px",
                    justifyContent: "flex-end",
                  }}
                >
                  <button
                    onClick={() =>
                      deleteDevice(selectedDevice.id, selectedDevice.name)
                    }
                    style={{
                      background: "#ef4444",
                      color: "white",
                      border: "none",
                      padding: "10px 16px",
                      borderRadius: "8px",
                      fontSize: "14px",
                      cursor: "pointer",
                      fontWeight: "500",
                    }}
                  >
                    Delete Device
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* User Profile Modal */}
      {showUserProfile && (
        <div
          style={{
            position: "fixed",
            top: "0",
            left: "0",
            right: "0",
            bottom: "0",
            background: "rgba(0, 0, 0, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: "#ffffff",
              borderRadius: "16px",
              padding: "32px",
              width: "90%",
              maxWidth: "500px",
              maxHeight: "90vh",
              overflowY: "auto",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "24px",
              }}
            >
              <h2
                style={{
                  margin: "0",
                  fontSize: "20px",
                  fontWeight: "600",
                  color: "#1e293b",
                }}
              >
                User Profile
              </h2>
              <button
                onClick={() => setShowUserProfile(false)}
                style={{
                  background: "none",
                  border: "none",
                  color: "#64748b",
                  cursor: "pointer",
                  fontSize: "20px",
                }}
              >
                ✕
              </button>
            </div>

            <div
              style={{ display: "flex", flexDirection: "column", gap: "24px" }}
            >
              {/* Profile Information */}
              <div>
                <h3
                  style={{
                    margin: "0 0 16px 0",
                    fontSize: "16px",
                    fontWeight: "600",
                    color: "#1e293b",
                  }}
                >
                  Profile Information
                </h3>
                <form
                  onSubmit={updateProfile}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "16px",
                  }}
                >
                  <div>
                    <label
                      style={{
                        display: "block",
                        marginBottom: "4px",
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#374151",
                      }}
                    >
                      Full Name
                    </label>
                    <input
                      type="text"
                      value={profileUpdate.full_name}
                      onChange={(e) =>
                        setProfileUpdate({
                          ...profileUpdate,
                          full_name: e.target.value,
                        })
                      }
                      style={{
                        width: "100%",
                        padding: "10px 12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "6px",
                        fontSize: "14px",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>

                  <div>
                    <label
                      style={{
                        display: "block",
                        marginBottom: "4px",
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#374151",
                      }}
                    >
                      Email Address
                    </label>
                    <input
                      type="email"
                      value={profileUpdate.email}
                      onChange={(e) =>
                        setProfileUpdate({
                          ...profileUpdate,
                          email: e.target.value,
                        })
                      }
                      style={{
                        width: "100%",
                        padding: "10px 12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "6px",
                        fontSize: "14px",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: "12px",
                    }}
                  >
                    <div>
                      <label
                        style={{
                          display: "block",
                          marginBottom: "4px",
                          fontSize: "14px",
                          fontWeight: "500",
                          color: "#374151",
                        }}
                      >
                        Phone
                      </label>
                      <input
                        type="text"
                        value={profileUpdate.phone}
                        onChange={(e) =>
                          setProfileUpdate({
                            ...profileUpdate,
                            phone: e.target.value,
                          })
                        }
                        style={{
                          width: "100%",
                          padding: "10px 12px",
                          border: "1px solid #e2e8f0",
                          borderRadius: "6px",
                          fontSize: "14px",
                          boxSizing: "border-box",
                        }}
                      />
                    </div>

                    <div>
                      <label
                        style={{
                          display: "block",
                          marginBottom: "4px",
                          fontSize: "14px",
                          fontWeight: "500",
                          color: "#374151",
                        }}
                      >
                        Company
                      </label>
                      <input
                        type="text"
                        value={profileUpdate.company}
                        onChange={(e) =>
                          setProfileUpdate({
                            ...profileUpdate,
                            company: e.target.value,
                          })
                        }
                        style={{
                          width: "100%",
                          padding: "10px 12px",
                          border: "1px solid #e2e8f0",
                          borderRadius: "6px",
                          fontSize: "14px",
                          boxSizing: "border-box",
                        }}
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    style={{
                      padding: "12px",
                      background: loading ? "#94a3b8" : "#6366f1",
                      color: "white",
                      border: "none",
                      borderRadius: "8px",
                      cursor: loading ? "not-allowed" : "pointer",
                      fontSize: "14px",
                      fontWeight: "500",
                    }}
                  >
                    {loading ? "Updating..." : "Update Profile"}
                  </button>
                </form>
              </div>

              {/* Change Password */}
              <div
                style={{ borderTop: "1px solid #e2e8f0", paddingTop: "24px" }}
              >
                <h3
                  style={{
                    margin: "0 0 16px 0",
                    fontSize: "16px",
                    fontWeight: "600",
                    color: "#1e293b",
                  }}
                >
                  Change Password
                </h3>
                <form
                  onSubmit={changePassword}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "16px",
                  }}
                >
                  <div>
                    <label
                      style={{
                        display: "block",
                        marginBottom: "4px",
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#374151",
                      }}
                    >
                      Current Password
                    </label>
                    <input
                      type="password"
                      value={passwordChange.current_password}
                      onChange={(e) =>
                        setPasswordChange({
                          ...passwordChange,
                          current_password: e.target.value,
                        })
                      }
                      style={{
                        width: "100%",
                        padding: "10px 12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "6px",
                        fontSize: "14px",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>

                  <div>
                    <label
                      style={{
                        display: "block",
                        marginBottom: "4px",
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#374151",
                      }}
                    >
                      New Password
                    </label>
                    <input
                      type="password"
                      value={passwordChange.new_password}
                      onChange={(e) =>
                        setPasswordChange({
                          ...passwordChange,
                          new_password: e.target.value,
                        })
                      }
                      style={{
                        width: "100%",
                        padding: "10px 12px",
                        border: "1px solid #e2e8f0",
                        borderRadius: "6px",
                        fontSize: "14px",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={
                      loading ||
                      !passwordChange.current_password ||
                      !passwordChange.new_password
                    }
                    style={{
                      padding: "12px",
                      background:
                        loading ||
                        !passwordChange.current_password ||
                        !passwordChange.new_password
                          ? "#94a3b8"
                          : "#10b981",
                      color: "white",
                      border: "none",
                      borderRadius: "8px",
                      cursor:
                        loading ||
                        !passwordChange.current_password ||
                        !passwordChange.new_password
                          ? "not-allowed"
                          : "pointer",
                      fontSize: "14px",
                      fontWeight: "500",
                    }}
                  >
                    {loading ? "Changing..." : "Change Password"}
                  </button>
                </form>
              </div>

              {/* Account Info */}
              <div
                style={{ borderTop: "1px solid #e2e8f0", paddingTop: "24px" }}
              >
                <h3
                  style={{
                    margin: "0 0 16px 0",
                    fontSize: "16px",
                    fontWeight: "600",
                    color: "#1e293b",
                  }}
                >
                  Account Information
                </h3>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                    fontSize: "14px",
                    color: "#64748b",
                  }}
                >
                  <div>
                    <strong>Username:</strong> {userProfile.username}
                  </div>
                  <div>
                    <strong>Role:</strong> {userProfile.role || "Administrator"}
                  </div>
                  <div>
                    <strong>Member since:</strong>{" "}
                    {userProfile.created_at
                      ? new Date(userProfile.created_at).toLocaleDateString()
                      : "N/A"}
                  </div>
                  {userProfile.last_login && (
                    <div>
                      <strong>Last login:</strong>{" "}
                      {new Date(userProfile.last_login).toLocaleString()}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Device Modal - Enhanced */}
      {showAddDevice && (
        <div
          style={{
            position: "fixed",
            top: "0",
            left: "0",
            right: "0",
            bottom: "0",
            background: "rgba(0, 0, 0, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: "#ffffff",
              borderRadius: "16px",
              padding: "32px",
              width: "90%",
              maxWidth: "600px",
              maxHeight: "90vh",
              overflowY: "auto",
            }}
          >
            <h2
              style={{
                margin: "0 0 24px 0",
                fontSize: "20px",
                fontWeight: "600",
                color: "#1e293b",
              }}
            >
              Add New Device
            </h2>

            <form
              onSubmit={addDevice}
              style={{ display: "flex", flexDirection: "column", gap: "20px" }}
            >
              {/* Device Name */}
              <div>
                <label
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "14px",
                    fontWeight: "500",
                    color: "#374151",
                  }}
                >
                  Device Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g., Production Web Server"
                  value={newDevice.name}
                  onChange={(e) =>
                    setNewDevice({ ...newDevice, name: e.target.value })
                  }
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    fontSize: "14px",
                    boxSizing: "border-box",
                  }}
                  required
                />
              </div>

              {/* Device Type */}
              <div>
                <label
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "14px",
                    fontWeight: "500",
                    color: "#374151",
                  }}
                >
                  Device Type *
                </label>
                <select
                  value={newDevice.device_type}
                  onChange={(e) =>
                    setNewDevice({ ...newDevice, device_type: e.target.value })
                  }
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    fontSize: "14px",
                    boxSizing: "border-box",
                  }}
                >
                  {deviceTypes.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Operating System */}
              <div>
                <label
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "14px",
                    fontWeight: "500",
                    color: "#374151",
                  }}
                >
                  Operating System *
                </label>
                <select
                  value={newDevice.operating_system}
                  onChange={(e) =>
                    setNewDevice({
                      ...newDevice,
                      operating_system: e.target.value,
                    })
                  }
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    fontSize: "14px",
                    boxSizing: "border-box",
                  }}
                >
                  {Object.entries(groupedOS).map(([category, systems]) => (
                    <optgroup key={category} label={`─── ${category} ───`}>
                      {systems.map((os) => (
                        <option key={os.value} value={os.value}>
                          {os.label}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              </div>

              {/* OS Version */}
              <div>
                <label
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "14px",
                    fontWeight: "500",
                    color: "#374151",
                  }}
                >
                  OS Version *
                </label>
                <input
                  type="text"
                  placeholder="e.g., 22.04 LTS, 11 Pro, 14.1"
                  value={newDevice.os_version}
                  onChange={(e) =>
                    setNewDevice({ ...newDevice, os_version: e.target.value })
                  }
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    fontSize: "14px",
                    boxSizing: "border-box",
                  }}
                  required
                />
              </div>

              {/* Network Information */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "16px",
                }}
              >
                <div>
                  <label
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#374151",
                    }}
                  >
                    IP Address
                  </label>
                  <input
                    type="text"
                    placeholder="192.168.1.100"
                    value={newDevice.ip_address}
                    onChange={(e) =>
                      setNewDevice({ ...newDevice, ip_address: e.target.value })
                    }
                    style={{
                      width: "100%",
                      padding: "12px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      boxSizing: "border-box",
                    }}
                  />
                </div>

                <div>
                  <label
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#374151",
                    }}
                  >
                    Hostname
                  </label>
                  <input
                    type="text"
                    placeholder="web-server-01"
                    value={newDevice.hostname}
                    onChange={(e) =>
                      setNewDevice({ ...newDevice, hostname: e.target.value })
                    }
                    style={{
                      width: "100%",
                      padding: "12px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      boxSizing: "border-box",
                    }}
                  />
                </div>
              </div>

              {/* Environment and Priority */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "16px",
                }}
              >
                <div>
                  <label
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#374151",
                    }}
                  >
                    Environment
                  </label>
                  <select
                    value={newDevice.environment}
                    onChange={(e) =>
                      setNewDevice({
                        ...newDevice,
                        environment: e.target.value,
                      })
                    }
                    style={{
                      width: "100%",
                      padding: "12px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      boxSizing: "border-box",
                    }}
                  >
                    <option value="development">🟦 Development</option>
                    <option value="testing">🟨 Testing</option>
                    <option value="staging">🟧 Staging</option>
                    <option value="production">🟥 Production</option>
                  </select>
                </div>

                <div>
                  <label
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#374151",
                    }}
                  >
                    Business Priority
                  </label>
                  <select
                    value={newDevice.business_criticality}
                    onChange={(e) =>
                      setNewDevice({
                        ...newDevice,
                        business_criticality: e.target.value,
                      })
                    }
                    style={{
                      width: "100%",
                      padding: "12px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      boxSizing: "border-box",
                    }}
                  >
                    <option value="low">🟢 Low Priority</option>
                    <option value="medium">🟡 Medium Priority</option>
                    <option value="high">🟠 High Priority</option>
                    <option value="critical">🔴 Critical System</option>
                  </select>
                </div>
              </div>

              {/* Additional Info */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "16px",
                }}
              >
                <div>
                  <label
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#374151",
                    }}
                  >
                    Location
                  </label>
                  <input
                    type="text"
                    placeholder="Server Room A"
                    value={newDevice.location}
                    onChange={(e) =>
                      setNewDevice({ ...newDevice, location: e.target.value })
                    }
                    style={{
                      width: "100%",
                      padding: "12px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      boxSizing: "border-box",
                    }}
                  />
                </div>

                <div>
                  <label
                    style={{
                      display: "block",
                      marginBottom: "8px",
                      fontSize: "14px",
                      fontWeight: "500",
                      color: "#374151",
                    }}
                  >
                    Owner Contact
                  </label>
                  <input
                    type="text"
                    placeholder="admin@company.com"
                    value={newDevice.owner_contact}
                    onChange={(e) =>
                      setNewDevice({
                        ...newDevice,
                        owner_contact: e.target.value,
                      })
                    }
                    style={{
                      width: "100%",
                      padding: "12px 16px",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      fontSize: "14px",
                      boxSizing: "border-box",
                    }}
                  />
                </div>
              </div>

              {/* Description */}
              <div>
                <label
                  style={{
                    display: "block",
                    marginBottom: "8px",
                    fontSize: "14px",
                    fontWeight: "500",
                    color: "#374151",
                  }}
                >
                  Description
                </label>
                <textarea
                  placeholder="Device description..."
                  value={newDevice.description}
                  onChange={(e) =>
                    setNewDevice({ ...newDevice, description: e.target.value })
                  }
                  rows="3"
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    fontSize: "14px",
                    boxSizing: "border-box",
                    resize: "vertical",
                  }}
                />
              </div>

              {/* Action Buttons */}
              <div style={{ display: "flex", gap: "12px", marginTop: "16px" }}>
                <button
                  type="button"
                  onClick={() => setShowAddDevice(false)}
                  style={{
                    flex: 1,
                    padding: "12px",
                    background: "#f8fafc",
                    color: "#64748b",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    cursor: "pointer",
                    fontSize: "14px",
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    flex: 1,
                    padding: "12px",
                    background: loading ? "#94a3b8" : "#6366f1",
                    color: "white",
                    border: "none",
                    borderRadius: "8px",
                    cursor: loading ? "not-allowed" : "pointer",
                    fontSize: "14px",
                    fontWeight: "500",
                  }}
                >
                  {loading ? "Adding Device..." : "Add Device"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Toast Message */}
      {message && (
        <div
          style={{
            position: "fixed",
            bottom: "24px",
            right: "24px",
            background: message.includes("✅") ? "#10b981" : "#ef4444",
            color: "white",
            padding: "16px 20px",
            borderRadius: "8px",
            fontSize: "14px",
            fontWeight: "500",
            zIndex: 1000,
            boxShadow: "0 4px 12px rgba(0, 0, 0, 0.15)",
          }}
        >
          {message}
        </div>
      )}
    </div>
  );
};

export default Dashboard;
