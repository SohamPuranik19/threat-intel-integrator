# Changelog

All notable changes to the Threat Intel Integrator project.

## [2.0.0] - 2025-11-03

### Added - Major Frontend Overhaul

#### New React/Next.js Frontend
- ✨ **Modern UI**: Complete Next.js/React frontend with Tailwind CSS
- 🎨 **Dark Theme**: Beautiful dark mode design with cyan/blue color scheme
- 📱 **Responsive Layout**: Mobile-friendly grid layout with sidebar
- ⚡ **Hot Reload**: Development mode with instant updates

#### Enhanced Components
- **SearchBar Component**:
  - Loading states for search and table loading
  - Improved error handling with visual feedback
  - Success messages with auto-dismiss
  - Quick search buttons (Google DNS, Google.com, Malicious Example)
  - Better input validation
  - Disabled states during operations

- **QuickVerdict Component**:
  - Enhanced visual design with status-based colors
  - Large, readable threat score display
  - Detailed metadata grid (Country, ISP, DNS, MX records)
  - Smooth fade-in animations
  - Better classification badges
  - Support for both API and heuristic data

- **DataTable Component**:
  - 📊 Export to CSV functionality
  - 🔍 Real-time filtering by indicator/category/source
  - 🏷️ Filter by classification (Benign/Suspicious/Malicious)
  - ⬆️⬇️ Sortable columns (Indicator, Classification, Score, Timestamp)
  - Visual sort indicators
  - Hover effects on rows
  - Row count display
  - Pagination info (first 100 results)

#### Backend Improvements
- 🌐 **CORS Support**: Added CORSMiddleware for frontend-backend communication
- 🔍 **Optional Query**: `/search` endpoint now works without query parameter
- 📝 **Better Response Format**: Consistent JSON responses with count and items

#### Testing & Documentation
- 🧪 **Smoke Tests**: Automated test script (`tests/smoke_test.sh`) covering:
  - Frontend accessibility (HTTP 200)
  - Frontend title verification
  - Backend `/search` endpoint
  - Backend `/lookup` endpoint
  - JSON response validation
  - CORS configuration
- 📚 **Comprehensive README**: Complete setup and usage documentation
- 📖 **API Documentation**: Clear endpoint descriptions and examples

#### Features
- ✅ Multi-source threat intelligence integration
- ✅ Real-time indicator lookup
- ✅ Bulk data loading and analysis
- ✅ CSV export for offline analysis
- ✅ Advanced filtering and sorting
- ✅ Visual threat classification
- ✅ Responsive design for all devices

### Changed
- Updated `api_server.py` with CORS middleware
- Modified `/search` endpoint to accept optional query parameter
- Enhanced error responses with detailed messages
- Improved CSS with animations and transitions

### Fixed
- CSS syntax error: `to-white/2` → `to-white/20`
- CORS blocking frontend API calls
- Search endpoint requiring query parameter
- Loading states not showing during operations
- Error messages not displaying properly

### Technical Details
- **Frontend Stack**: Next.js 14, React, TypeScript, Tailwind CSS, Axios, Lucide Icons
- **Backend Stack**: FastAPI, Python 3.9+, SQLite, Pandas
- **Testing**: Bash-based smoke tests with curl and jq
- **Development**: Hot-reload enabled on both frontend and backend

---

## [1.0.0] - Previous Version

### Features
- Streamlit dashboard for threat intelligence
- SQLite database for local storage
- Integration with VirusTotal, AbuseIPDB, AlienVault OTX
- Email authentication
- Heuristic analysis without API keys

---

## Future Enhancements

### Planned Features
- [ ] Dark mode toggle switch
- [ ] Advanced charts and visualizations
- [ ] Detailed indicator view modal
- [ ] Real-time API status indicators
- [ ] Batch upload from CSV
- [ ] Historical trend analysis
- [ ] API rate limiting display
- [ ] User preferences storage
- [ ] Indicator timeline view
- [ ] Threat actor attribution
- [ ] Integration with more threat feeds
- [ ] WebSocket support for real-time updates

---

**For detailed setup instructions, see [README.md](README.md)**
