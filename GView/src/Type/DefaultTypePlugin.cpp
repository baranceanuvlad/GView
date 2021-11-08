#include "GViewApp.hpp"

using namespace GView::Utils;
using namespace GView;

class DefaultType: public TypeInterface
{
  public:
    std::string_view GetTypeName() override
    {
        return "GENERIC";
    }
    ~DefaultType()
    {
    }
};

class DefaultInformationPanel : public TabPage
{
  public:
    DefaultInformationPanel(Reference<Object> obj) : TabPage("&Information")
    {
        auto lv = this->CreateChildControl<ListView>("d:c", ListViewFlags::None);
        lv->AddColumn("Field", TextAlignament::Left, 10);
        lv->AddColumn("Value", TextAlignament::Left, 100);
    }
};

namespace GView::Type::DefaultTypePlugin
{
bool Validate(const GView::Utils::Buffer& buf, const std::string_view& extension)
{
    return true; // always match everything
}
TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> fileCache)
{
    return new DefaultType();
}

bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    // at least one view and one information panel
    // 1. info panel
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), true);
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), true);
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), false);
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), false);

    // 2. views
    auto v = win->AddBufferView("Buffer view");
    return true;
}
} // namespace GView::Type::DefaultTypePlugin