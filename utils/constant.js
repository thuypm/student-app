const CONSTANT = {
  WEEKDAY_COLUMNS: [
    {
      label: "Thứ 2",
      value: "MONDAY",
    },
    {
      label: "Thứ 3",
      value: "TUESDAY",
    },
    {
      label: "Thứ 4",
      value: "WEDNESDAY",
    },
    {
      label: "Thứ 5",
      value: "THUSDAY",
    },
    {
      label: "Thứ 6",
      value: "FRIDAY",
    },
    {
      label: "Thứ 7",
      value: "SATURDAY",
    },
    {
      label: "CN",
      value: "SUNDAY",
    },
  ],
  EVALUATE_COLUMNS: [
    {
      label: "X.dựng bài trên 3 lần",
      value: 0,
    },
    {
      label: "K.tra bài cũ trên 9 ",
      value: 1,
    },
    {
      label: "K.tra đề chung trên 9",
      value: 2,
    },
    {
      label: "V.nghệ, T.dục,...",
      value: 3,
    },
    {
      label: "Mất trật tự",
      value: 4,
    },
    {
      label: "Đổi chỗ",
      value: 5,
    },
    {
      label: "Thiếu đồ dùng",
      value: 6,
    },
    {
      label: "K.tra bài cũ dưới 5",
      value: 7,
    },
    {
      label: "X.dựng bài dưới 3 lần",
      value: 8,
    },
    {
      label: "Thiếu đ.phục",
      value: 9,
    },
    {
      label: "Thiếu thẻ h.sinh",
      value: 10,
    },
    {
      label: "Đi xe trong sân trường, không đội mũ bh",
      value: 11,
    },
    {
      label: "Đánh nhau",
      value: 12,
    },
    {
      label: "V.phạm ATGT",
      value: 13,
    },
    {
      label: "Điểm trừ theo đơn vị trường",
      value: 14,
    },
    {
      label: "Đi muộn, vắng ko phép ",
      value: 15,
    },
  ],
  ALL_STUDENTS: [
    {
      id: "1",
      name: "Ngô Phương Anh",
    },
    {
      id: "2",
      name: "Tăng Thị Hải Anh",
    },
    {
      id: "3",
      name: "Ngô Thị Ánh",
    },
    {
      id: "4",
      name: "Phạm Thị Ngọc Ánh",
    },
    {
      id: "5",
      name: "Nguyễn Xuân Bách",
    },
    {
      id: "6",
      name: "Trịnh Khắc Bách",
    },
    {
      id: "7",
      name: "Nguyễn Hữu Thanh Bình",
    },
    {
      id: "8",
      name: "Vũ Đăng Công",
    },
    {
      id: "9",
      name: "Đỗ Đắc Duy",
    },
    {
      id: "10",
      name: "Ngô Đức Duy",
    },
    {
      id: "11",
      name: "Phạm Bạch Dương",
    },
    {
      id: "12",
      name: "Phạm Thùy Dương",
    },
    {
      id: "13",
      name: "Đỗ Hữu Đạt",
    },
    {
      id: "14",
      name: "Nguyễn Xuân Hải Đăng",
    },
    {
      id: "15",
      name: "Nguyễn Hữu Đoàn",
    },
    {
      id: "16",
      name: "Phan Thu Hiền",
    },
    {
      id: "17",
      name: "Ngô Đức Hiếu",
    },
    {
      id: "18",
      name: "Nguyễn Đình Hiếu",
    },
    {
      id: "19",
      name: "Tiêu Trung Hiếu",
    },
    {
      id: "20",
      name: "Lương Thế Hiệp",
    },
    {
      id: "21",
      name: "Nguyễn Thị Hoa",
    },
    {
      id: "22",
      name: "Nguyễn Quang Hoàng",
    },
    {
      id: "23",
      name: "Nguyễn Duy Hữu",
    },
    {
      id: "24",
      name: "Cao Xuân Mạnh",
    },
    {
      id: "25",
      name: "Nguyễn Văn Minh",
    },
    {
      id: "26",
      name: "Nguyễn Thị Kim Ngân",
    },
    {
      id: "27",
      name: "Tăng Xuân Nghĩa",
    },
    {
      id: "28",
      name: "Phạm Tiến Sơn",
    },
    {
      id: "29",
      name: "Bùi Thị Phương Thảo",
    },
    {
      id: "30",
      name: "Nguyễn Thị Thanh Thảo",
    },
    {
      id: "31",
      name: "Vũ Thị Thu Thảo",
    },
    {
      id: "32",
      name: "Phạm Minh Thắng",
    },
    {
      id: "33",
      name: "Bùi Thị Thủy",
    },
    {
      id: "34",
      name: "Ngô Văn Tiệp",
    },
    {
      id: "35",
      name: "Nguyễn Quang Toản",
    },
    {
      id: "36",
      name: "Lê Việt Trung",
    },
    {
      id: "37",
      name: "Bùi Thanh Trúc",
    },
    {
      id: "38",
      name: "Bùi Hữu Tuấn",
    },
    {
      id: "39",
      name: "Nguyễn Anh Tuấn",
    },
    {
      id: "40",
      name: "Phạm Thị Ánh Tuyết",
    },
    {
      id: "41",
      name: "Nguyễn Đặng Tùng",
    },
    {
      id: "42",
      name: "Đặng Quốc Việt",
    },
    {
      id: "43",
      name: "Vũ Văn Vinh",
    },
  ],
  ALL_WEEKS: [
    {
      id: "22",
      name: "Tuần 22",
    },
    {
      id: "23",
      name: "Tuần 23",
    },
    {
      id: "24",
      name: "Tuần 24",
    },
    {
      id: "25",
      name: "Tuần 25",
    },
    {
      id: "26",
      name: "Tuần 26",
    },
    {
      id: "27",
      name: "Tuần 27",
    },
    {
      id: "28",
      name: "Tuần 28",
    },
    {
      id: "29",
      name: "Tuần 29",
    },
    {
      id: "30",
      name: "Tuần 30",
    },
    {
      id: "31",
      name: "Tuần 31",
    },
    {
      id: "32",
      name: "Tuần 32",
    },
    {
      id: "33",
      name: "Tuần 33",
    },
    {
      id: "34",
      name: "Tuần 34",
    },
    {
      id: "35",
      name: "Tuần 35",
    },
    {
      id: "36",
      name: "Tuần 36",
    },
    {
      id: "37",
      name: "Tuần 37",
    },
    {
      id: "38",
      name: "Tuần 38",
    },
    {
      id: "39",
      name: "Tuần 39",
    },
    {
      id: "40",
      name: "Tuần 40",
    },
    {
      id: "41",
      name: "Tuần 41",
    },
    {
      id: "42",
      name: "Tuần 42",
    },
    {
      id: "43",
      name: "Tuần 43",
    },
    {
      id: "44",
      name: "Tuần 44",
    },
    {
      id: "45",
      name: "Tuần 45",
    },
    {
      id: "46",
      name: "Tuần 46",
    },
    {
      id: "47",
      name: "Tuần 47",
    },
    {
      id: "48",
      name: "Tuần 48",
    },
    {
      id: "49",
      name: "Tuần 49",
    },
    {
      id: "50",
      name: "Tuần 50",
    },
    {
      id: "51",
      name: "Tuần 51",
    },
    {
      id: "52",
      name: "Tuần 52",
    },
    {
      id: "53",
      name: "Tuần 53",
    },
    {
      id: "54",
      name: "Tuần 54",
    },
    {
      id: "55",
      name: "Tuần 55",
    },
    {
      id: "56",
      name: "Tuần 56",
    },
    {
      id: "57",
      name: "Tuần 57",
    },
    {
      id: "58",
      name: "Tuần 58",
    },
    {
      id: "59",
      name: "Tuần 59",
    },
    {
      id: "60",
      name: "Tuần 60",
    },
    {
      id: "61",
      name: "Tuần 61",
    },
    {
      id: "62",
      name: "Tuần 62",
    },
    {
      id: "63",
      name: "Tuần 63",
    },
    {
      id: "64",
      name: "Tuần 64",
    },
  ],
};

module.exports = CONSTANT;
