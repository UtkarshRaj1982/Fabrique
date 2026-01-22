import React from "react";
import {
  FaBoxOpen,
  FaClipboardList,
  FaSignOutAlt,
  FaStore,
  FaUser,
  FaTachometerAlt
} from "react-icons/fa";
import { useDispatch } from "react-redux";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { logout } from "../../../redux/slice/authSlice";
import { clearCart } from "../../../redux/slice/cartSlice";

const AdminSidebar = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const handleLogout = () => {
    dispatch(logout());
    dispatch(clearCart());
    navigate("/");
  };

  return (
    <div className="p-6 text-sm md:text-base">
      {/* Logo */}
      <div className="mb-8">
      <h2 className="text-3xl font-bold text-white tracking-wide">
        Fabrique
      </h2>
      </div>

      {/* Heading */}
       <Link
  to="/admin"
  className="text-lg font-bold text-white px-5 py-2 mb-1 flex items-center gap-2 tracking-wide rounded-md hover:bg-gray-800 transition-colors duration-200"
>
  <FaTachometerAlt />
  Admin Panel
</Link>

      {/* Navigation */}
      <nav className="flex flex-col space-y-2">
        {[
          { to: "/admin/users", icon: <FaUser />, label: "Users" },
          { to: "/admin/products", icon: <FaBoxOpen />, label: "Products" },
          { to: "/admin/orders", icon: <FaClipboardList />, label: "Orders" },
          { to: "/", icon: <FaStore />, label: "Shop" },
        ].map(({ to, icon, label }) => (
          <NavLink
            key={label}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-md transition-colors duration-200 ${
                isActive
                  ? "bg-gray-700 text-white"
                  : "text-gray-300 hover:bg-gray-800 hover:text-white"
              }`
            }
          >
            {icon}
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Logout Button */}
      <div className="mt-8">
        <button
          onClick={handleLogout}
          className="w-full flex items-center justify-center gap-3 px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-md transition-colors duration-200"
        >
          <FaSignOutAlt />
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
};

export default AdminSidebar;
