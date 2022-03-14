/*
 * @Author: Diantao Tu
 * @Date: 2022-03-13 19:01:08
 */


#define PCD_DURATION 0.1        // 每个pcd包含的扫描时间


#define SCANS 16             // 雷达扫描线数
#define FIRING_CYCLE 2.304      // 相邻两束雷达发射的时间间隔，单位是微秒 us
#define RECHARGEING_TIME 18.432     // 发射完16束激光后，需要重新充能，这是充能的时间，单位是微秒
#define SEQUENCE_TIME (FIRING_CYCLE * SCANS + RECHARGEING_TIME)     // 两列扫描之间的间隔
#define HORIZON_SPEED 3600          // 雷达一秒内旋转的角度
#define D2R (M_PI / 180.0)
float vertical_angle[SCANS] =               // 雷达扫描的垂直角度，以度为单位。这里的顺序是发射的顺序。
        {-15 * D2R, 1 * D2R, -13 * D2R, 3 * D2R, -11 * D2R, 5 * D2R, -9 * D2R, 7 * D2R,
        -7 * D2R, 9 * D2R, -5 * D2R, 11 * D2R, -3 * D2R, 13 * D2R, -1 * D2R, 15 * D2R};
float vertical_correction[SCANS] =          // 雷达每根线垂直方向上的矫正，以毫米为单位。不太明白是干什么的。
        {11.2, -0.7, 9.7, -2.2, 8.1, -3.7, 6.6, -5.1,
         5.1, -6.6, 3.7, -8.1, 2.2, -9.7, 0.7, -11.2};

// 不同型号雷达的product id
enum PRODUCT_ID
{
    HDL_32E = 0x21,
    VLP_16 = 0x22,
    PUCK_LITE = 0x22,
    PUCK_HI_RES = 0x24,
    VLP_32C = 0x28,
    VELARRAY = 0x31,
    VLS_128 = 0x63
};

enum RETURN_MODE
{
    STRONGUST = 0x37,
    LAST_RETURN = 0x38,
    DUAL_RETURN = 0x39
};