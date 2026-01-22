import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { clearCart } from "../../redux/slice/cartSlice";

const OrderConfirmationPage = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { checkout } = useSelector((state) => state.checkout);

  useEffect(() => {
    if (checkout && checkout._id) {
      dispatch(clearCart());
      localStorage.removeItem("cart");
    } else {
      navigate("/my-orders");
    }
  }, [checkout, dispatch, navigate]);

  const calculateEstimatedDelivery = (createdAt) => {
    const orderDate = new Date(createdAt);
    orderDate.setDate(orderDate.getDate() + 10);
    return orderDate.toLocaleDateString();
  };

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white dark:bg-gray-900 min-h-screen">
      <h1 className="text-3xl sm:text-4xl font-bold text-center text-emerald-700 dark:text-emerald-400 mb-8">
        Thank You for Your Order!
      </h1>

      {checkout && (
        <div className="p-6 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-md">
          {/* Order Info */}
          <div className="flex flex-col sm:flex-row justify-between mb-12">
            <div className="mb-4 sm:mb-0">
              <h2 className="text-lg sm:text-xl font-semibold text-gray-800 dark:text-white">
                Order ID: <span className="text-gray-700 dark:text-gray-300">{checkout._id}</span>
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Order Date: {new Date(checkout.createdAt).toLocaleString()}
              </p>
            </div>
            <div>
              <p className="text-emerald-700 dark:text-emerald-400 text-sm font-medium">
                Estimated Delivery: {calculateEstimatedDelivery(checkout.createdAt)}
              </p>
            </div>
          </div>

          {/* Items List */}
          <div className="space-y-6 mb-12">
            {checkout.checkoutItems.map((item) => (
              <div
                key={item.productId}
                className="flex items-center gap-4 border-b border-gray-100 dark:border-gray-700 pb-4"
              >
                <img
                  src={item.image}
                  alt={item.name}
                  className="w-16 h-16 object-cover rounded-md"
                />
                <div className="flex-1">
                  <h4 className="text-base font-semibold text-gray-800 dark:text-gray-200">{item.name}</h4>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {item.color} | {item.size}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-sm sm:text-base font-medium text-gray-900 dark:text-gray-100">${item.price}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Qty: {item.quantity}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Payment & Shipping */}
          <div className="grid sm:grid-cols-2 gap-8">
            <div>
              <h4 className="text-lg font-semibold mb-2 text-gray-800 dark:text-gray-200">Payment</h4>
              <p className="text-gray-600 dark:text-gray-400">PayPal</p>
            </div>
            <div>
              <h4 className="text-lg font-semibold mb-2 text-gray-800 dark:text-gray-200">Delivery Address</h4>
              <p className="text-gray-600 dark:text-gray-400">
                {checkout.shippingAddress.address}
              </p>
              <p className="text-gray-600 dark:text-gray-400">
                {checkout.shippingAddress.city}, {checkout.shippingAddress.country}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrderConfirmationPage;
