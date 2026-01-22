import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import PaypalButton from "./PaypalButton";
import { useDispatch, useSelector } from "react-redux";
import { createCheckout } from "../../../redux/slice/checkoutSlice";
import axios from "axios";

const Checkout = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { cart, loading, error } = useSelector((state) => state.cart);
  const { user } = useSelector((state) => state.auth);

  const [CheckoutId, setCheckOutId] = useState(null);
  const [shippingAddress, setShippingAddress] = useState({
    firstName: "",
    lastName: "",
    city: "",
    address: "",
    postalCode: "",
    country: "",
    phone: "",
  });

  //Ensure cart is not loaded before proceeding
  useEffect(() => {
    if (!cart || !cart.products || cart.products.length === 0) {
      navigate("/");
    }
  }, [cart, navigate]);

  const handleCreateCheckout = async (e) => {
    e.preventDefault();
    if (cart && cart.products.length > 0) {
      const res = await dispatch(
        createCheckout({
          checkoutItems: cart.products,
          shippingAddress,
          paymentMethod: "Paypal",
          totalPrice: cart.totalPrice,
        })
      );
      if (res.payload && res.payload._id) {
        setCheckOutId(res.payload._id); // set checkout ID if checkout was successful
      }
    }
  };
  const handlePaymentSuccess = async (details) => {
    try {
      const response = await axios.put(
        `${import.meta.env.VITE_BACKEND_URL}/api/checkout/${CheckoutId}/pay`,
        { paymentStatus: "paid", paymentDetails: details },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("userToken")}`,
          },
        }
      );

      await handleFinalizedCheckout(CheckoutId); // Finalize checkout if payment is successful
    } catch (error) {
      console.error(error);
    }
  };

  const handleFinalizedCheckout = async (CheckoutId) => {
    try {
      const response = await axios.post(
        `${
          import.meta.env.VITE_BACKEND_URL
        }/api/checkout/${CheckoutId}/finalize`,
        {},
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("userToken")}`,
          },
        }
      );
      navigate("/order-confirmation");
    } catch (error) {
      console.error(error);
    }
  };

  if (loading) return <p>Loading cart ...</p>;
  if (error) return <p>Error: {error}</p>;
  if ((!cart && !cart.products) || cart.products.length === 0) {
    return <p>Your cart is empty</p>;
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 max-w-7xl mx-auto py-10 px-6">
      {/* Left: Form Section */}
      <div className="bg-white rounded-2xl shadow-md p-8">
        <h2 className="text-3xl font-bold mb-8">Checkout</h2>
        <form onSubmit={handleCreateCheckout} className="space-y-6">
          <div>
            <h3 className="text-lg font-semibold mb-4">Contact Details</h3>
            <input
              type="email"
              value={user ? user.email : ""}
              className="w-full p-3 border border-gray-300 rounded-lg bg-gray-100"
              disabled
            />
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-4">Delivery</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <input
                type="text"
                placeholder="First Name"
                className="p-3 border border-gray-300 rounded-lg"
                value={shippingAddress.firstName}
                onChange={(e) =>
                  setShippingAddress({
                    ...shippingAddress,
                    firstName: e.target.value,
                  })
                }
                required
              />
              <input
                type="text"
                placeholder="Last Name"
                className="p-3 border border-gray-300 rounded-lg"
                value={shippingAddress.lastName}
                onChange={(e) =>
                  setShippingAddress({
                    ...shippingAddress,
                    lastName: e.target.value,
                  })
                }
                required
              />
            </div>
            <input
              type="text"
              placeholder="Address"
              className="w-full mt-4 p-3 border border-gray-300 rounded-lg"
              value={shippingAddress.address}
              onChange={(e) =>
                setShippingAddress({
                  ...shippingAddress,
                  address: e.target.value,
                })
              }
              required
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              <input
                type="text"
                placeholder="City"
                className="p-3 border border-gray-300 rounded-lg"
                value={shippingAddress.city}
                onChange={(e) =>
                  setShippingAddress({
                    ...shippingAddress,
                    city: e.target.value,
                  })
                }
                required
              />
              <input
                type="text"
                placeholder="Postal Code"
                className="p-3 border border-gray-300 rounded-lg"
                value={shippingAddress.postalCode}
                onChange={(e) =>
                  setShippingAddress({
                    ...shippingAddress,
                    postalCode: e.target.value,
                  })
                }
                required
              />
            </div>
            <input
              type="text"
              placeholder="Country"
              className="w-full mt-4 p-3 border border-gray-300 rounded-lg"
              value={shippingAddress.country}
              onChange={(e) =>
                setShippingAddress({
                  ...shippingAddress,
                  country: e.target.value,
                })
              }
              required
            />
            <input
              type="text"
              placeholder="Phone"
              className="w-full mt-4 p-3 border border-gray-300 rounded-lg"
              value={shippingAddress.phone}
              onChange={(e) =>
                setShippingAddress({
                  ...shippingAddress,
                  phone: e.target.value,
                })
              }
              required
            />
          </div>

          <div className="pt-6">
            {!CheckoutId ? (
              <button
                type="submit"
                className="w-full bg-black text-white py-3 rounded-lg text-lg hover:bg-gray-800 transition"
              >
                Continue to Payment
              </button>
            ) : (
              <div>
                <h3 className="text-lg font-semibold mb-4">Pay with PayPal</h3>
                <PaypalButton
                  amount={cart.totalPrice}
                  onSuccess={handlePaymentSuccess}
                  onError={() => alert("Payment failed, please try again.")}
                />
              </div>
            )}
          </div>
        </form>
      </div>

      {/* Right: Summary */}
      <div className="bg-gray-50 p-8 rounded-2xl shadow-sm">
        <h3 className="text-xl font-semibold mb-6">Order Summary</h3>
        <div className="divide-y">
          {cart.products.map((product, index) => (
            <div key={index} className="flex justify-between items-start py-4">
              <div className="flex gap-4">
                <img
                  src={product.image}
                  alt={product.name}
                  className="w-20 h-24 object-cover rounded-md"
                />
                <div>
                  <p className="font-medium">{product.name}</p>
                  <p className="text-sm text-gray-500">Size: {product.size}</p>
                  <p className="text-sm text-gray-500">
                    Color: {product.color}
                  </p>
                </div>
              </div>
              <p className="font-semibold text-gray-800">
                ₹{product.price?.toLocaleString()}
              </p>
            </div>
          ))}
        </div>
        <div className="border-t pt-4 mt-6 space-y-2 text-lg font-medium">
          <div className="flex justify-between">
            <span>Subtotal</span>
            <span>₹{cart.totalPrice?.toLocaleString()}</span>
          </div>
          <div className="flex justify-between">
            <span>Shipping</span>
            <span className="text-green-600 font-semibold">Free</span>
          </div>
          <div className="flex justify-between pt-2 border-t">
            <span>Total</span>
            <span className="text-xl font-bold">
              ₹{cart.totalPrice?.toLocaleString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Checkout;
