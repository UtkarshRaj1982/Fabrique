import { Link, useLocation } from "react-router-dom";
import {
  HiOutlineUser,
  HiOutlineShoppingBag,
  HiBars3BottomRight,
} from "react-icons/hi2";
import { IoMdClose } from "react-icons/io";
import { useSelector } from "react-redux";
import { useEffect, useState } from "react";
import SearchBar from "./SearchBar";
import CartDrawer from "../Layout/CartDrawer";


const Navbar = () => {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const { cart } = useSelector((state) => state.cart);
  const { user } = useSelector((state) => state.auth);
  const location = useLocation();

  const cartItemCount =
    cart?.products?.reduce((total, product) => total + product.quantity, 0) || 0;

  const toggleNavDrawer = () => setNavDrawerOpen(!navDrawerOpen);
  const toggleCartDrawer = () => setDrawerOpen(!drawerOpen);

  // Auto-close nav drawer on route change
  useEffect(() => {
    setNavDrawerOpen(false);
  }, [location.pathname]);

  return (
    <>
      <nav className="container mx-auto flex items-center justify-between py-4 px-6">
        {/* Logo */}
        <Link to="/" className="text-2xl font-semibold tracking-tight">
          Fabrique
        </Link>

        {/* Nav links (Desktop) */}
        <div className="hidden md:flex space-x-6">
          {["Men", "Women"].map((gender) => (
            <Link
              key={gender}
              to={`/collections/all?gender=${gender}`}
              className="text-gray-700 hover:text-black text-sm font-medium uppercase"
            >
              {gender}
            </Link>
          ))}
          {["Top Wear", "Bottom Wear"].map((cat) => (
            <Link
              key={cat}
              to={`/collections/all?category=${cat}`}
              className="text-gray-700 hover:text-black text-sm font-medium uppercase"
            >
              {cat}
            </Link>
          ))}
        </div>

        {/* Right Icons */}
        <div className="flex items-center space-x-4">
          {/* Admin badge */}
          {user?.role === "admin" && (
            <Link
              to="/admin"
              className="bg-black text-white text-sm px-2 py-1 rounded font-medium hover:bg-gray-900"
            >
              Admin
            </Link>
          )}

          {/* Profile icon */}
          <Link to="/profile" aria-label="Profile">
            <HiOutlineUser className="h-6 w-6 text-gray-700 hover:text-black" />
          </Link>

          {/* Cart icon */}
          <button
            onClick={toggleCartDrawer}
            className="relative hover:text-black"
            aria-label="Open cart"
          >
            <HiOutlineShoppingBag className="h-6 w-6 text-gray-700" />
            {cartItemCount > 0 && (
              <span className="absolute -top-1 -right-2 bg-red-600 text-white text-xs rounded-full px-1.5 py-0.5 leading-none">
                {cartItemCount}
              </span>
            )}
          </button>

          {/* Search */}
          <div className="hidden md:block w-40">
            <SearchBar />
          </div>

          {/* Hamburger (Mobile) */}
          <button onClick={toggleNavDrawer} className="md:hidden" aria-label="Toggle menu">
            <HiBars3BottomRight className="h-6 w-6 text-gray-700" />
          </button>
        </div>
      </nav>

      {/* Cart Drawer */}
      <CartDrawer drawerOpen={drawerOpen} toggleCartDrawer={toggleCartDrawer} />

      {/* Overlay for mobile nav */}
      {navDrawerOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-30 z-40"
          onClick={toggleNavDrawer}
        ></div>
      )}

      {/* Mobile nav drawer */}
      <div
        className={`fixed top-0 left-0 w-3/4 sm:w-1/2 md:w-1/3 h-full bg-white shadow-lg transform transition-transform duration-300 z-50 ${
          navDrawerOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-lg font-semibold">Menu</h2>
          <button onClick={toggleNavDrawer} aria-label="Close menu">
            <IoMdClose className="h-6 w-6 text-gray-600" />
          </button>
        </div>
        <nav className="p-4 space-y-4 text-gray-600">
          {["Men", "Women"].map((gender) => (
            <Link
              key={gender}
              to={`/collections/all?gender=${gender}`}
              className="block hover:text-black"
            >
              {gender}
            </Link>
          ))}
          {["Top Wear", "Bottom Wear"].map((cat) => (
            <Link
              key={cat}
              to={`/collections/all?category=${cat}`}
              className="block hover:text-black"
            >
              {cat}
            </Link>
          ))}
        </nav>
      </div>
    </>
  );
};

export default Navbar;
