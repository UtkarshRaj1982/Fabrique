import { IoMdClose } from "react-icons/io";
import CartContents from "../Cart/CartContents";
import { useNavigate } from "react-router-dom";
import { useSelector } from "react-redux";

const CartDrawer = ({ drawerOpen, toggleCartDrawer }) => {
  const navigate = useNavigate();
  const { user, guestId } = useSelector((state) => state.auth);
  const { cart } = useSelector((state) => state.cart);
  const userId = user ? user._id : null;

  const handleCheckout = () => {
    toggleCartDrawer();
    if (!user) {
      navigate("/login?redirect=checkout");
    } else {
      navigate("/checkout");
    }
  };

  return (
    <div
      className={`fixed top-0 right-0 w-3/4 sm:w-1/2 md:w-[30rem] h-full 
        bg-white shadow-lg transform transition-transform duration-300 
        flex flex-col z-50 ${
          drawerOpen ? "translate-x-0" : "translate-x-full"
        }`}
    >
      {/* Close Button */}
      <div className="flex justify-end p-4 border-b">
        <button onClick={toggleCartDrawer} aria-label="Close cart">
          <IoMdClose className="h-6 w-6 text-gray-600 hover:text-black" />
        </button>
      </div>

      {/* Scrollable Cart Content */}
      <div className="flex-grow p-4 overflow-y-auto">
        <h2 className="text-xl font-semibold mb-4">Your Cart</h2>
        {cart?.products?.length > 0 ? (
          <CartContents cart={cart} userId={userId} guestId={guestId} />
        ) : (
          <p className="text-gray-500">Your cart is empty.</p>
        )}
      </div>

      {/* Checkout Button */}
      {cart?.products?.length > 0 && (
        <div className="p-4 bg-white border-t">
          <button
            onClick={handleCheckout}
            className="w-full bg-black text-white py-3 rounded-lg font-semibold hover:bg-gray-800"
          >
            Checkout
          </button>
          <p className="text-sm text-center text-gray-500 mt-2 tracking-tight">
            Shipping, taxes & discounts calculated at checkout.
          </p>
        </div>
      )}
    </div>
  );
};

export default CartDrawer;
