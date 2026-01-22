import React, { useEffect } from "react";
import MyOrderPage from "./MyOrderPage";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { clearCart } from "../../redux/slice/cartSlice";
import { logout } from "../../redux/slice/authSlice";
import Avatar from "react-avatar";

const Profile = () => {
  const { user } = useSelector((state) => state.auth);
  const navigate = useNavigate();
  const dispatch = useDispatch();

  useEffect(() => {
    if (!user) {
      navigate("/login");
    }
  }, [user, navigate]);

  const handleLogout = () => {
    dispatch(logout());
    dispatch(clearCart());
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-white">
      <div className="container mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Profile Card */}
          <div className="bg-white dark:bg-gray-800 shadow-md rounded-lg p-6 space-y-4">
            <div className="text-center">
              <Avatar
                name={user?.name}
                size="96"
                round={true}
                color="#ea2e0e"
                fgColor="#fff"
                className="mx-auto mb-4"
              />
              <h1 className="text-2xl font-semibold">{user?.name}</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {user?.email}
              </p>
            </div>
            <button
              onClick={handleLogout}
              className="w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition"
            >
              Log Out
            </button>
          </div>

          {/* Orders Section */}
          <div className="md:col-span-2">
            <div className="bg-white dark:bg-gray-800 shadow-md rounded-lg p-4 sm:p-6">
              <MyOrderPage />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
