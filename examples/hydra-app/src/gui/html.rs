use super::{assets::INDEX_HTML, encoding::json_escape};

pub(crate) fn render_index_html(token: &str) -> String {
    INDEX_HTML.replace("__HYDRA_GUI_TOKEN__", &json_escape(token))
}
