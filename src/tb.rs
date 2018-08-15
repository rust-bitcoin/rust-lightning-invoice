pub trait Bool {}
pub struct True {}
pub struct False {}

impl Bool for True {}
impl Bool for False {}