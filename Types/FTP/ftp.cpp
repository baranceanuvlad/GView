#include "ftp.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C" {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    if (buf.GetLength() < sizeof(JPG::Header) + sizeof(JPG::App0MarkerSegment)) {
        return false;
    }
    auto header = buf.GetObject<JPG::Header>();
    if (header->soi != JPG::JPG_SOI_MARKER || header->app0 != JPG::JPG_APP0_MARKER) {
        return false;
    }
    auto app0MarkerSegment = buf.GetObject<JPG::App0MarkerSegment>(sizeof(JPG::Header));
    if (memcmp(app0MarkerSegment->identifier, "JFIF", 5) != 0) {
        return false;
    }
    return true;
}
}

int main()
{
    return 0;
}