import React, { useState } from "react";
import { FaBars } from "react-icons/fa";
import AdminSidebar from "./AdminSidebar";
import { Outlet } from "react-router-dom";

const AdminLayout = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-gray-100 text-gray-800">
      {/* Mobile Toggle Button at Navbar */}
      <div className="flex md:hidden items-center justify-between px-4 py-3 bg-gray-900 text-white shadow-md z-20">
        <div className="flex items-center">
          <button onClick={toggleSidebar} className="focus:outline-none">
            <FaBars size={24} />
          </button>
          <h1 className="ml-4 text-lg font-semibold tracking-wide">
            Admin Dashboard
          </h1>
        </div>
      </div>

      {/* Mobile Sidebar Overlay */}
      {isSidebarOpen && (
        <div
          className="fixed inset-0 z-10 bg-black bg-opacity-50 md:hidden"
          onClick={toggleSidebar}
        ></div>
      )}

      {/* Sidebar */}
      <div
        className={`bg-gray-900 text-white w-64 md:relative absolute z-30 transform 
          ${isSidebarOpen ? "translate-x-0" : "-translate-x-full"} 
          transition-transform duration-300 ease-in-out md:translate-x-0 md:block shadow-lg`}
      >
        <AdminSidebar />
      </div>

      {/* Main Content */}
      <main className="flex-grow p-6 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
};

export default AdminLayout;
