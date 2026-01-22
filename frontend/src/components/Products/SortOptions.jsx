import React from "react";
import { useSearchParams } from "react-router-dom";

const SortOptions = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  const handleSortChange = (e) => {
    const sortBy = e.target.value;
    if (sortBy) {
      searchParams.set("sortBy", sortBy);
    } else {
      searchParams.delete("sortBy");
    }
    setSearchParams(searchParams);
  };

  return (
    <div className="mb-4 flex items-center justify-end">
      <label htmlFor="sort" className="mr-2 text-sm text-gray-700">
        Sort by:
      </label>
      <select
        id="sort"
        onChange={handleSortChange}
        value={searchParams.get("sortBy") || ""}
        className="border border-gray-300 p-2 rounded-md focus:outline-none focus:ring-2 focus:ring-black text-sm"
      >
        <option value="">Default</option>
        <option value="priceAsc">Price: Low to High</option>
        <option value="priceDesc">Price: High to Low</option>
        <option value="popularity">Popularity</option>
      </select>
    </div>
  );
};

export default SortOptions;
