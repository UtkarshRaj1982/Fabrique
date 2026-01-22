import React, { useEffect, useRef, useState } from "react";
import { FaFilter } from "react-icons/fa";
import FilterSidebar from "../components/Products/FilterSidebar";
import SortOptions from "../components/Products/SortOptions";
import ProductGrid from "../components/Products/ProductGrid";
import { useParams, useSearchParams } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { fetchProductsByFilter } from "../../redux/slice/productsSlice";

const CollectionPage = () => {
  const { collection } = useParams();
  const [searchParams] = useSearchParams();
  const dispatch = useDispatch();
  const { products, loading, error } = useSelector((state) => state.products);
  const queryParams = Object.fromEntries([...searchParams]);

  const sidebarRef = useRef(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  useEffect(() => {
    dispatch(fetchProductsByFilter({ collection, ...queryParams }));
  }, [dispatch, collection, searchParams]);

  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  const handleClickOutside = (e) => {
    if (sidebarRef.current && !sidebarRef.current.contains(e.target)) {
      setIsSidebarOpen(false);
    }
  };

  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className="flex flex-col lg:flex-row">
      {/* Mobile Filter Toggle Button */}
      <div className="lg:hidden p-4 border-b flex justify-between items-center">
        <h2 className="text-xl font-semibold uppercase">All Collection</h2>
        <button
          onClick={toggleSidebar}
          className="flex items-center gap-2 text-sm bg-gray-100 px-3 py-1 rounded"
        >
          <FaFilter />
          Filters
        </button>
      </div>

      {/* Sidebar */}
      <div
        ref={sidebarRef}
        className={`fixed inset-y-0 left-0 z-40 w-64 bg-white shadow-lg transition-transform duration-300 ease-in-out transform lg:static lg:translate-x-0 lg:shadow-none
          ${isSidebarOpen ? "translate-x-0" : "-translate-x-full"}`}
      >
        <FilterSidebar />
      </div>

      {/* Main Content */}
      <div className="flex-grow px-4 py-6">
        <div className="hidden lg:block">
          <h2 className="text-2xl font-bold uppercase mb-4">All Collection</h2>
        </div>

        {/* Sort Options */}
        <SortOptions />

        {/* Product Grid */}
        <ProductGrid products={products} loading={loading} error={error} />
      </div>
    </div>
  );
};

export default CollectionPage;
